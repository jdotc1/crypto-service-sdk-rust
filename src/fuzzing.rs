// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The response decoding paths without the network, for the cargo-fuzz
//! targets in `fuzz/` and the benches in `benches/`. Compiled only under
//! `cfg(fuzzing)` (which cargo-fuzz sets), with the `internals` feature,
//! and for unit tests, so it is not part of the public API of a normal
//! build.

use http::HeaderMap;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::transport::HttpResponse;
use crate::types::Envelope;
use crate::{Error, Problem};

/// What a call returns for an answer with `status` and `body`: the typed
/// result for a 2xx, an [`Error::Api`] otherwise.
///
/// # Errors
///
/// As every typed call.
pub fn decode<T: DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, Error> {
    crate::client::decode(HttpResponse {
        status,
        headers: HeaderMap::new(),
        body: body.to_vec(),
    })
}

/// [`decode`] for an answer wrapped in `{ "data": ... }`, as every v2
/// call but the CBOM.
///
/// # Errors
///
/// As every typed call.
pub fn decode_data<T: DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, Error> {
    decode::<Envelope<T>>(status, body).map(Envelope::into_data)
}

/// The problem a non-2xx answer with `body` becomes.
#[must_use]
pub fn problem(status: u16, body: &[u8]) -> Problem {
    Problem::from_body(status, body)
}

/// The JSON body a typed call sends for `request`.
///
/// # Errors
///
/// [`Error::Decode`] when `request` cannot be encoded.
pub fn encode<B: Serialize + ?Sized>(request: &B) -> Result<Vec<u8>, Error> {
    crate::client::encode(request)
}

#[cfg(test)]
mod tests;
