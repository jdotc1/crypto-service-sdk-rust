// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Request and response types, one module per area of the API.
//!
//! Field encodings follow the OpenAPI document exactly: [`Hex`] and
//! [`Base64`] for public binary values, [`SecretBytes`] and
//! [`SecretString`] for key material, passwords and plaintexts (zeroised
//! on drop, redacted in `Debug`), and `String` for text and identifiers.
//! Request enums are typed; response fields that echo an algorithm name
//! stay `String`, so a name a newer server adds still decodes.
//!
//! [`Hex`]: crate::Hex
//! [`Base64`]: crate::Base64
//! [`SecretBytes`]: crate::SecretBytes
//! [`SecretString`]: crate::SecretString

mod asymmetric;
mod hashing;
mod hpke;
mod kms;
mod meta;
mod opaque;
mod pq;
mod signing;
mod symmetric;

pub use asymmetric::*;
pub use hashing::*;
pub use hpke::*;
pub use kms::*;
pub use meta::*;
pub use opaque::*;
pub use pq::*;
pub use signing::*;
pub use symmetric::*;

use serde::{Deserialize, Serialize};

/// The `{ "data": ... }` wrapper of every v2 answer except the CBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Envelope<T> {
    pub(crate) data: T,
}

impl<T> Envelope<T> {
    /// The wrapped answer.
    pub(crate) fn into_data(self) -> T {
        self.data
    }
}

/// A request without parameters, sent as `{}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// A request naming one server-held key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyIdRequest {
    /// The key's identifier (`k_` and 22 base64url characters), from a
    /// key-generation call.
    pub key_id: String,
}

impl KeyIdRequest {
    /// A request for `key_id`.
    pub fn new(key_id: impl Into<String>) -> Self {
        KeyIdRequest {
            key_id: key_id.into(),
        }
    }
}

/// A server-held key pair: its identifier, algorithm and public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KeyPair {
    /// The algorithm, for example `ml-kem-768`.
    pub algorithm: String,
    /// The key's identifier.
    pub key_id: String,
    /// The public key.
    pub public_key: crate::Hex,
}

/// The answer of a verification: whether the signature or tag holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Verification {
    /// The algorithm used.
    pub algorithm: String,
    /// Whether it verified.
    pub valid: bool,
}

/// A signature and the algorithm that made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Signature {
    /// The algorithm, for example `ed25519`.
    pub algorithm: String,
    /// The signature.
    pub signature: crate::Hex,
}

/// A sealed box and its algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Sealed {
    /// The algorithm.
    pub algorithm: String,
    /// The sealed box.
    pub sealed: crate::Base64,
}

/// A ciphertext and its algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Ciphertext {
    /// The algorithm.
    pub algorithm: String,
    /// The ciphertext.
    pub ciphertext: crate::Base64,
}

/// A decrypted plaintext, as UTF-8 text (invalid sequences become U+FFFD).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Plaintext {
    /// The plaintext.
    pub plaintext: crate::SecretString,
}

#[cfg(test)]
mod tests;
