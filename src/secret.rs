// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Key material and secret text: zeroised on drop, redacted in `Debug`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{decode_hex, encode_hex, Text};

/// Secret bytes the API carries as hex: private and secret keys, shared
/// secrets, derived and unwrapped keys, data keys, symmetric keys sent to
/// the server.
///
/// The buffer is overwritten with zeros when the value is dropped, and
/// `Debug` prints `SecretBytes(<redacted>)`. There is no `Display` and no
/// `PartialEq`: read the bytes with [`SecretBytes::expose_secret`].
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

/// Secret text: passwords, plaintexts and the decrypted text the server
/// returns.
///
/// The buffer is overwritten with zeros when the value is dropped, and
/// `Debug` prints `SecretString(<redacted>)`. There is no `Display` and
/// no `PartialEq`: read the text with [`SecretString::expose_secret`].
#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretBytes {
    /// Wraps `bytes`, which are zeroised when this value is dropped.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// Reads hex text, either case.
    ///
    /// # Errors
    ///
    /// [`EncodingError`](crate::EncodingError) for text that is not hex.
    pub fn from_hex(text: &str) -> Result<Self, crate::EncodingError> {
        decode_hex(text).map(Self::new)
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl SecretString {
    /// Wraps `text`, which is zeroised when this value is dropped.
    pub fn new(text: impl Into<String>) -> Self {
        Self(Zeroizing::new(text.into()))
    }

    /// The secret text.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes {
    fn from(mut bytes: [u8; N]) -> Self {
        let secret = Self::new(bytes.to_vec());
        bytes.zeroize();
        secret
    }
}

impl From<String> for SecretString {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&str> for SecretString {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(encode_hex(&self.0));
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Text(|text: &str| Self::from_hex(text)))
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests;
