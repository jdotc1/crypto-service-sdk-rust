// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The blocking client (the `blocking` feature).
//!
//! Each [`Client`] owns a small Tokio runtime (one worker thread) and runs
//! the async client's call on it, so it has the same methods, options,
//! retries and errors. Create, use and drop it outside async code: inside
//! a Tokio runtime, call the async [`crate::Client`] instead.

use std::future::Future;
use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::error::Error;
use crate::transport::HttpResponse;
use crate::RawRequest;

/// A blocking client for one crypto-server.
///
/// Cheap to clone; clones share the runtime and the connection pool.
/// `Client` is `Send + Sync`: threads may call one instance at once, and
/// each call blocks only its own thread.
#[derive(Debug, Clone)]
pub struct Client {
    inner: crate::Client,
    runtime: Arc<Runtime>,
}

impl Client {
    /// A blocking client of `base_url` with every default.
    ///
    /// # Errors
    ///
    /// As [`crate::ClientBuilder::build`], or [`Error::Config`] when the
    /// runtime cannot start.
    pub fn new(base_url: impl Into<String>) -> Result<Self, Error> {
        crate::Client::new(base_url).and_then(Self::from_async)
    }

    /// Wraps an async client, built with [`crate::Client::builder`], so
    /// its options apply.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the runtime cannot start.
    pub fn from_async(inner: crate::Client) -> Result<Self, Error> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("crypto-service-sdk")
            .enable_all()
            .build()
            .map(|runtime| Client {
                inner,
                runtime: Arc::new(runtime),
            })
            .map_err(runtime_failed)
    }

    /// The async client this one drives.
    #[must_use]
    pub fn inner(&self) -> &crate::Client {
        &self.inner
    }

    /// The base URL, without a trailing `/`.
    #[must_use]
    pub fn base_url(&self) -> &str {
        self.inner.base_url()
    }

    /// [`crate::Client::send_raw`], blocking.
    ///
    /// # Errors
    ///
    /// As the async method.
    pub fn send_raw(&self, request: RawRequest) -> Result<HttpResponse, Error> {
        self.block_on(self.inner.send_raw(request))
    }

    pub(crate) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

/// The error for a runtime that could not start.
fn runtime_failed(_: std::io::Error) -> Error {
    Error::Config("the blocking client's runtime could not start")
}

#[cfg(test)]
mod tests;
