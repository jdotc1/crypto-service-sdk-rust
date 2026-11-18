// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed async and blocking client for the Crypto Service REST API.
//!
//! [crypto-server](https://github.com/sebastienrousseau/crypto-service)
//! exposes hashing, MACs, key derivation, AEAD, server-held signing and
//! decryption keys, ML-KEM, ML-DSA, SLH-DSA, HPKE, KMS and OPAQUE over
//! HTTP. This crate is a thin client for its v2 API: one method per
//! operation, and no cryptography of its own. Every operation is an HTTP
//! call to the server.
//!
//! ```no_run
//! use crypto_service_sdk::{Client, HashAlgorithm, HashRequest};
//!
//! # async fn run() -> Result<(), crypto_service_sdk::Error> {
//! let client = Client::builder("http://127.0.0.1:3000")
//!     .api_key("synthetic-api-key-0000000000000000")
//!     .build()?;
//! let digest = client
//!     .hash(&HashRequest {
//!         algorithm: HashAlgorithm::Sha256,
//!         data: "abc".into(),
//!     })
//!     .await?;
//! println!("{}", digest.digest);
//! # Ok(())
//! # }
//! ```
//!
//! A non-2xx answer becomes [`Error::Api`] with the server's RFC 9457
//! [`Problem`]; no answer at all becomes [`Error::Transport`]. Retries are
//! off unless a [`RetryPolicy`] turns them on, and a call that creates or
//! deletes server state is never retried after the server may have acted
//! on it. Keys, passwords and plaintexts travel in [`SecretBytes`] and
//! [`SecretString`], which are zeroised on drop and redacted in `Debug`.
//!
//! With the `blocking` feature, `blocking::Client` offers the same methods
//! without `async`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod builder;
mod client;
mod encoding;
mod error;
mod operations;
mod retry;
mod secret;
mod transport;
mod types;

#[cfg(feature = "blocking")]
pub mod blocking;

#[cfg(test)]
mod stub;

/// The decoding paths without the network, for `fuzz/` and `benches/`.
/// Not public API: it exists only under `cfg(fuzzing)`, with the
/// `internals` feature, and in unit tests.
#[cfg(any(fuzzing, test, feature = "internals"))]
#[doc(hidden)]
pub mod fuzzing;

pub use builder::{ClientBuilder, Traceparent};
pub use client::{Client, RawRequest, DEFAULT_TIMEOUT, USER_AGENT, VERSION};
pub use encoding::{Base64, EncodingError, Hex};
pub use error::{ApiError, DecodeError, Error, Problem, TransportError, ValidationError};
pub use retry::RetryPolicy;
pub use secret::{SecretBytes, SecretString};
pub use transport::{BoxFuture, HttpRequest, HttpResponse, ReqwestTransport, Transport};
pub use types::*;

/// `http`, re-exported for [`RawRequest`], [`HttpRequest`] and custom
/// [`Transport`]s.
pub use http;

/// Compiles the README's Rust snippets as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
