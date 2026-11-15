// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Byte strings as the API carries them: lowercase hex or standard base64.
//!
//! The OpenAPI document gives each binary field one encoding, and these
//! types follow it exactly. They only translate between bytes and text;
//! no cryptography happens here.

use std::fmt;
use std::ops::Deref;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bytes the API carries as lowercase hex (`contentEncoding: base16`):
/// public keys, signatures, digests, MACs, KEM ciphertexts and HPKE
/// output. Serialises as lowercase hex and reads either case.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Hex(Vec<u8>);

/// Bytes the API carries as standard base64 with padding
/// (`contentEncoding: base64`): AEAD, secretbox, sealed-box, stream,
/// password-encryption and AES key wrap output.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Base64(Vec<u8>);

/// A string that is not valid hex or base64.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not valid {0}")]
pub struct EncodingError(&'static str);

macro_rules! byte_string {
    ($name:ident) => {
        impl $name {
            /// Wraps `bytes`.
            pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
                Self(bytes.into())
            }

            /// The bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// The bytes, owned.
            #[must_use]
            pub fn into_vec(self) -> Vec<u8> {
                self.0
            }
        }

        impl Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl<const N: usize> From<[u8; N]> for $name {
            fn from(bytes: [u8; N]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_str(Text(Self::parse))
            }
        }
    };
}

byte_string!(Hex);
byte_string!(Base64);

impl Hex {
    /// Reads hex text, either case.
    ///
    /// # Errors
    ///
    /// [`EncodingError`] for an odd length or a non-hex character.
    pub fn parse(text: &str) -> Result<Self, EncodingError> {
        decode_hex(text).map(Self)
    }
}

impl Base64 {
    /// Reads standard base64 with padding.
    ///
    /// # Errors
    ///
    /// [`EncodingError`] for text that is not standard padded base64.
    pub fn parse(text: &str) -> Result<Self, EncodingError> {
        STANDARD
            .decode(text)
            .map(Self)
            .map_err(|_| EncodingError("base64"))
    }
}

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl fmt::Debug for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hex({self})")
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(&self.0))
    }
}

/// Shows the length only: a ciphertext is opaque, and long.
impl fmt::Debug for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Base64(<{} bytes>)", self.0.len())
    }
}

/// Lowercase hex of `bytes`.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// The bytes of hex text, either case.
pub(crate) fn decode_hex(text: &str) -> Result<Vec<u8>, EncodingError> {
    let digits = text.as_bytes();
    if digits.len() % 2 != 0 {
        return Err(EncodingError("hex"));
    }
    digits
        .chunks_exact(2)
        .map(|pair| Ok(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

fn nibble(digit: u8) -> Result<u8, EncodingError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(EncodingError("hex")),
    }
}

/// A serde visitor for a string, parsed by `.0`.
pub(crate) struct Text<F>(pub(crate) F);

impl<T, F> Visitor<'_> for Text<F>
where
    F: FnOnce(&str) -> Result<T, EncodingError>,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an encoded byte string")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        (self.0)(text).map_err(E::custom)
    }
}

#[cfg(test)]
mod tests;
