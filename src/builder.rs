// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Client options and their checks.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use zeroize::Zeroizing;

use crate::client::{Client, Inner, API_KEY, TRACEPARENT, USER_AGENT};
use crate::error::Error;
use crate::retry::RetryPolicy;
use crate::transport::{ReqwestTransport, Transport};
use crate::SecretString;

/// The W3C `traceparent` header the client sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Traceparent {
    /// None (the default).
    #[default]
    Off,
    /// A fresh `traceparent` per call, kept across that call's retries.
    Auto,
    /// This value on every call.
    Fixed(String),
}

/// Options for a [`Client`]; start with [`Client::builder`].
///
/// `Debug` output shows whether credentials are set, never their values.
#[derive(Clone)]
#[must_use]
pub struct ClientBuilder {
    pub(crate) base_url: String,
    pub(crate) api_key: Option<SecretString>,
    pub(crate) token: Option<SecretString>,
    pub(crate) timeout: Duration,
    pub(crate) deadline: Option<Duration>,
    pub(crate) retry: RetryPolicy,
    pub(crate) traceparent: Traceparent,
    pub(crate) transport: Option<Arc<dyn Transport>>,
}

impl ClientBuilder {
    /// Sends `key` as `x-api-key` on every call (the server's
    /// `CRYPTO_API_KEY`).
    pub fn api_key(mut self, key: impl Into<SecretString>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Sends `token` as `Authorization: Bearer <token>` on every call (an
    /// HS256 JWT the server accepts).
    pub fn token(mut self, token: impl Into<SecretString>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Sets the timeout of each attempt (default 30 s). `Duration::ZERO`
    /// turns it off.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets an overall deadline for a call, retries and waits included
    /// (default none).
    pub fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Sets the retry policy (default: no retries).
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    /// Sets the `traceparent` header (default none).
    pub fn traceparent(mut self, traceparent: Traceparent) -> Self {
        self.traceparent = traceparent;
        self
    }

    /// Sends every request through `transport` instead of the default
    /// [`ReqwestTransport`]; for tests and custom stacks.
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for a base URL that is not an absolute `http` or
    /// `https` URL, or has credentials, a query or a fragment in it; for a
    /// credential or `traceparent` that is not a valid header value; or
    /// when the TLS stack cannot be initialised.
    pub fn build(self) -> Result<Client, Error> {
        let base_url = check_base_url(&self.base_url)?;
        let headers = self.headers()?;
        let auto_traceparent = self.traceparent == Traceparent::Auto;
        let (timeout, deadline, retry) = (self.timeout, self.deadline, self.retry);
        self.transport
            .map_or_else(default_transport, Ok)
            .map(|transport| Client {
                inner: Arc::new(Inner {
                    base_url,
                    headers,
                    timeout,
                    deadline,
                    retry,
                    auto_traceparent,
                    transport,
                }),
            })
    }

    /// The headers every request carries.
    pub(crate) fn headers(&self) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static(USER_AGENT),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, application/problem+json"),
        );
        if let Some(key) = &self.api_key {
            headers.insert(API_KEY, secret_header(key.expose_secret())?);
        }
        if let Some(token) = &self.token {
            let bearer = Zeroizing::new(format!("Bearer {}", token.expose_secret()));
            headers.insert(AUTHORIZATION, secret_header(&bearer)?);
        }
        if let Traceparent::Fixed(value) = &self.traceparent {
            let value = HeaderValue::from_str(value.trim())
                .map_err(|_| Error::Config("traceparent is not a valid header value"))?;
            if !value.is_empty() {
                headers.insert(TRACEPARENT, value);
            }
        }
        Ok(headers)
    }
}

/// The default transport, shared by the client and its clones.
fn default_transport() -> Result<Arc<dyn Transport>, Error> {
    ReqwestTransport::new().map(|transport| Arc::new(transport) as Arc<dyn Transport>)
}

/// A credential as a header value marked sensitive.
fn secret_header(value: &str) -> Result<HeaderValue, Error> {
    let mut header = HeaderValue::from_str(value)
        .map_err(|_| Error::Config("a credential is not a valid header value"))?;
    header.set_sensitive(true);
    Ok(header)
}

/// The base URL without a trailing `/`, once it is known to be an
/// absolute `http` or `https` URL without credentials, query or fragment.
fn check_base_url(base_url: &str) -> Result<String, Error> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| Error::Config("the base URL is not an absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Config("the base URL is not http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config("the base URL carries credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Config("the base URL has a query or fragment"));
    }
    Ok(base_url.trim_end_matches('/').to_owned())
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("deadline", &self.deadline)
            .field("retry", &self.retry)
            .field("traceparent", &self.traceparent)
            .finish_non_exhaustive()
    }
}
