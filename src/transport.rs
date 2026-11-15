// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The HTTP exchange under every call, replaceable for tests.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use http::{HeaderMap, Method};

use crate::error::TransportError;

/// Largest response body read, in bytes.
pub(crate) const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// A boxed, sendable future, as [`Transport::send`] returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sends one HTTP request and reads the whole answer.
///
/// The default is [`ReqwestTransport`]. A custom one (a recording
/// wrapper, an in-process fake) goes in with
/// [`ClientBuilder::transport`](crate::ClientBuilder::transport). The
/// client applies the per-attempt timeout, the deadline, retries and
/// error mapping around it; a transport only moves bytes, and answers
/// every status, 2xx or not, as an `Ok`.
pub trait Transport: Send + Sync + fmt::Debug {
    /// Sends `request` and returns the answer, or a [`TransportError`]
    /// when none arrived.
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>>;
}

/// One request, as the client hands it to a [`Transport`].
///
/// `Debug` shows the method, URL and header names only: the values carry
/// credentials and the body carries keys and plaintexts.
#[derive(Clone)]
pub struct HttpRequest {
    /// The method.
    pub method: Method,
    /// The absolute URL.
    pub url: String,
    /// Every header the client sets, credentials included.
    pub headers: HeaderMap,
    /// The JSON body, when there is one.
    pub body: Option<Vec<u8>>,
}

/// One answer, of any status.
///
/// `Debug` shows the status, header names and body length only.
#[derive(Clone)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The response headers.
    pub headers: HeaderMap,
    /// The whole body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The `Content-Type` without parameters, for example
    /// `application/problem+json`; empty when absent.
    #[must_use]
    pub fn media_type(&self) -> &str {
        self.headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map_or("", str::trim)
    }

    /// A header's value, when present and visible ASCII.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &self.body.len())
            .finish()
    }
}

/// The default [`Transport`]: one pooled `reqwest` client per SDK client
/// and its clones, with rustls (the platform's trust store, verification
/// always on), HTTP/2 by ALPN, gzip, keep-alive, and redirects refused.
/// Responses are read up to 64 MiB.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    limit: usize,
}

impl ReqwestTransport {
    /// A transport with the SDK's settings.
    ///
    /// # Errors
    ///
    /// [`Error::Config`](crate::Error::Config) when the TLS stack cannot
    /// be initialised.
    pub fn new() -> Result<Self, crate::Error> {
        Self::with_limit(BODY_LIMIT)
    }

    /// [`ReqwestTransport::new`] reading bodies up to `limit` bytes.
    pub(crate) fn with_limit(limit: usize) -> Result<Self, crate::Error> {
        reqwest::Client::builder()
            // A redirect would carry the credentials to whatever origin
            // the Location names; an API never needs one.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(|client| ReqwestTransport { client, limit })
            .map_err(build_failed)
    }

    async fn exchange(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = self
            .client
            .request(request.method, request.url)
            .headers(request.headers);
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(failure)?;
        let status = response.status().as_u16();
        let headers = std::mem::take(response.headers_mut());
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(failure)? {
            if body.len() + chunk.len() > self.limit {
                return Err(TransportError::new(
                    "response body over the size limit",
                    false,
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(self.exchange(request))
    }
}

/// The error for a `reqwest` client that could not be built.
pub(crate) fn build_failed(_: reqwest::Error) -> crate::Error {
    crate::Error::Config("the HTTP client could not be built")
}

/// A reqwest error as a [`TransportError`], without the URL.
fn failure(error: reqwest::Error) -> TransportError {
    let timed_out = error.is_timeout();
    TransportError::new(error.without_url(), timed_out)
}
