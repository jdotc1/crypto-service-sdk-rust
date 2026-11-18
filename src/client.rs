// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The async client: the request pipeline and decoding.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use http::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::builder::{ClientBuilder, Traceparent};
use crate::error::{ApiError, DecodeError, Error, Problem, TransportError};
use crate::retry::{is_idempotent, random, RetryPolicy};
use crate::transport::{HttpRequest, HttpResponse, Transport};
use crate::types::Envelope;

/// The per-attempt timeout of a new client, until
/// [`ClientBuilder::timeout`] changes it.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// This crate's version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `User-Agent` every request sends: `crypto-service-sdk-rust/<VERSION>`.
pub const USER_AGENT: &str = concat!("crypto-service-sdk-rust/", env!("CARGO_PKG_VERSION"));

pub(crate) const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
pub(crate) const API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// A client for one crypto-server.
///
/// Cheap to clone: clones share one connection pool and one set of
/// options. `Client` is `Send + Sync`, so one instance (or its clones) can
/// serve any number of tasks and threads at once. Dropping a call's
/// future cancels it. `Debug` output never shows the credentials.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) base_url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) timeout: Duration,
    pub(crate) deadline: Option<Duration>,
    pub(crate) retry: RetryPolicy,
    pub(crate) auto_traceparent: bool,
    pub(crate) transport: Arc<dyn Transport>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = &self.inner;
        f.debug_struct("Client")
            .field("base_url", &inner.base_url)
            .field("api_key", &redacted(&inner.headers, &API_KEY))
            .field("token", &redacted(&inner.headers, &AUTHORIZATION))
            .field("timeout", &inner.timeout)
            .field("deadline", &inner.deadline)
            .field("retry", &inner.retry)
            .field("transport", &inner.transport)
            .finish_non_exhaustive()
    }
}

/// `Some("<redacted>")` when the header is set.
fn redacted(headers: &HeaderMap, name: &HeaderName) -> Option<&'static str> {
    headers.contains_key(name).then_some("<redacted>")
}

/// A request for [`Client::send_raw`]: any method and path, with an
/// optional body and extra headers.
#[derive(Debug, Clone)]
pub struct RawRequest {
    /// The method.
    pub method: Method,
    /// The path, from `/`, for example `/v2/hash`; any other is refused.
    pub path: String,
    /// The body, sent as it is; `Content-Type: application/json` unless
    /// `headers` sets another.
    pub body: Option<Vec<u8>>,
    /// Extra headers; they replace the client's own of the same name.
    pub headers: HeaderMap,
}

impl RawRequest {
    /// A request with no body and no extra headers.
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        RawRequest {
            method,
            path: path.into(),
            body: None,
            headers: HeaderMap::new(),
        }
    }

    /// A request whose body is `body` as JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] when `body` cannot be encoded as JSON.
    pub fn json<B: Serialize + ?Sized>(
        method: Method,
        path: impl Into<String>,
        body: &B,
    ) -> Result<Self, Error> {
        let mut request = Self::new(method, path);
        encode(body).map(|bytes| {
            request.body = Some(bytes);
            request
        })
    }
}

impl Client {
    /// Options for a client of the server at `base_url`, for example
    /// `https://crypto.example.com` or `http://127.0.0.1:3000`.
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.into(),
            api_key: None,
            token: None,
            timeout: DEFAULT_TIMEOUT,
            deadline: None,
            retry: RetryPolicy::default(),
            traceparent: Traceparent::Off,
            transport: None,
        }
    }

    /// A client of `base_url` with every default.
    ///
    /// # Errors
    ///
    /// As [`ClientBuilder::build`].
    pub fn new(base_url: impl Into<String>) -> Result<Self, Error> {
        Self::builder(base_url).build()
    }

    /// The base URL, without a trailing `/`.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    /// Sends any request, with the client's credentials, timeout, deadline
    /// and retries, and returns the answer whatever its status: the escape
    /// hatch for the deprecated v1 routes, `/metrics` and anything newer
    /// than this crate.
    ///
    /// # Errors
    ///
    /// [`Error::Config`], with nothing sent, when the path does not start
    /// with `/`: appended to the base URL, such a path could name another
    /// host (`.evil.example`, `@evil.example`) and receive the
    /// credentials. [`Error::Transport`] when no answer arrived; never
    /// [`Error::Api`].
    pub async fn send_raw(&self, request: RawRequest) -> Result<HttpResponse, Error> {
        let RawRequest {
            method,
            path,
            body,
            headers,
        } = request;
        if !path.starts_with('/') {
            return Err(Error::Config("the request path does not start with /"));
        }
        self.exchange(method, &path, body, headers).await
    }

    /// `method path` with `body`, decoded as `T`. Generic code stays
    /// branch-free; the branches live in the non-generic helpers.
    pub(crate) async fn call<B, T>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, Error>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let body = body.map(encode).transpose();
        self.send_encoded(method, path, body).await.and_then(decode)
    }

    /// [`Client::call`] for an answer wrapped in `{ "data": ... }`.
    pub(crate) async fn call_data<B, T>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, Error>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        self.call::<B, Envelope<T>>(method, path, body)
            .await
            .map(Envelope::into_data)
    }

    /// Sends an encoded body, or returns the encoding error unsent.
    async fn send_encoded(
        &self,
        method: Method,
        path: &str,
        body: Result<Option<Vec<u8>>, Error>,
    ) -> Result<HttpResponse, Error> {
        match body {
            Ok(body) => self.exchange(method, path, body, HeaderMap::new()).await,
            Err(error) => Err(error),
        }
    }

    /// Sends the request under the deadline, the retry policy and the
    /// per-attempt timeout.
    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        extra: HeaderMap,
    ) -> Result<HttpResponse, Error> {
        let inner = &self.inner;
        let idempotent = is_idempotent(&method, path);
        let request = HttpRequest {
            headers: self.request_headers(body.is_some(), extra),
            method,
            url: format!("{}{}", inner.base_url, path),
            body,
        };
        let attempts = self.attempts(request, idempotent);
        let outcome = match inner.deadline {
            Some(deadline) => tokio::time::timeout(deadline, attempts)
                .await
                .unwrap_or_else(|_| Err(TransportError::deadline())),
            None => attempts.await,
        };
        outcome.map_err(Error::from)
    }

    /// The client's headers, the call's `traceparent` and content type,
    /// then `extra`.
    fn request_headers(&self, has_body: bool, extra: HeaderMap) -> HeaderMap {
        let mut headers = self.inner.headers.clone();
        if self.inner.auto_traceparent {
            headers.insert(TRACEPARENT, traceparent());
        }
        if has_body {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        headers.extend(extra);
        headers
    }

    /// Attempts until the policy says the outcome is the result.
    async fn attempts(
        &self,
        request: HttpRequest,
        idempotent: bool,
    ) -> Result<HttpResponse, TransportError> {
        let policy = self.inner.retry;
        if policy.get_max_retries() == 0 {
            return self.attempt(request).await;
        }
        let mut retry = 1;
        loop {
            let outcome = self.attempt(request.clone()).await;
            let wait = match &outcome {
                Ok(response) => policy.after_status(
                    retry,
                    response.status,
                    response.header("retry-after"),
                    idempotent,
                ),
                Err(_) => policy.after_failure(retry, idempotent),
            };
            match wait {
                Some(wait) => tokio::time::sleep(wait).await,
                None => return outcome,
            }
            retry += 1;
        }
    }

    /// One attempt under the per-attempt timeout.
    async fn attempt(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let send = self.inner.transport.send(request);
        if self.inner.timeout.is_zero() {
            return send.await;
        }
        tokio::time::timeout(self.inner.timeout, send)
            .await
            .unwrap_or_else(|_| Err(TransportError::attempt_timeout()))
    }
}

/// A fresh W3C `traceparent`: version 00, random trace and parent IDs
/// (never all zero), sampled.
fn traceparent() -> HeaderValue {
    let value = format!(
        "00-{:016x}{:016x}-{:016x}-01",
        random() | 1,
        random(),
        random() | 1
    );
    HeaderValue::from_str(&value).unwrap_or(HeaderValue::from_static(
        "00-00000000000000000000000000000001-0000000000000001-01",
    ))
}

/// `body` as JSON bytes.
pub(crate) fn encode<B: Serialize + ?Sized>(body: &B) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(body).map_err(decode_error)
}

/// A 2xx answer decoded as `T`, any other as [`Error::Api`].
pub(crate) fn decode<T: DeserializeOwned>(response: HttpResponse) -> Result<T, Error> {
    success_body(response).and_then(|body| serde_json::from_slice(&body).map_err(decode_error))
}

/// The body of a 2xx answer, zeroised when dropped; any other status as
/// [`Error::Api`] with its problem.
fn success_body(response: HttpResponse) -> Result<Zeroizing<Vec<u8>>, Error> {
    let status = response.status;
    let body = Zeroizing::new(response.body);
    if (200..300).contains(&status) {
        return Ok(body);
    }
    Err(Error::from(ApiError {
        status,
        problem: Problem::from_body(status, &body),
    }))
}

/// A body that did not decode, as [`Error::Decode`].
fn decode_error(error: serde_json::Error) -> Error {
    Error::Decode(DecodeError::from(error))
}

#[cfg(test)]
mod tests;
