// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HPKE (RFC 9180) with classical and post-quantum KEMs.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Hex, SecretBytes, SecretString};

/// HPKE KEMs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum HpkeKem {
    /// DHKEM(X25519, HKDF-SHA256).
    X25519,
    /// DHKEM(P-256, HKDF-SHA256).
    P256,
    /// X-Wing (X25519 and ML-KEM-768), the server's default.
    #[default]
    XWing,
    /// X25519 and ML-KEM-768 hybrid.
    #[serde(rename = "x25519-ml-kem-768")]
    X25519MlKem768,
}

/// HPKE AEADs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum HpkeAead {
    /// ChaCha20-Poly1305.
    #[default]
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// AES-128-GCM.
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
}

/// An HPKE input (plaintext, `info`, `aad`).
///
/// The server reads an even-length hex string as hex and anything else as
/// UTF-8. So the SDK never leaves that to chance: [`HpkeData::Bytes`] is
/// always sent as hex, and [`HpkeData::Text`] is sent as is unless it
/// would read as hex, in which case its UTF-8 bytes are sent as hex.
/// Either way the server sees exactly the bytes meant.
#[derive(Clone)]
pub enum HpkeData {
    /// UTF-8 text.
    Text(SecretString),
    /// Bytes.
    Bytes(SecretBytes),
}

impl Default for HpkeData {
    fn default() -> Self {
        HpkeData::Text(SecretString::default())
    }
}

impl fmt::Debug for HpkeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeData(<redacted>)")
    }
}

impl From<&str> for HpkeData {
    fn from(text: &str) -> Self {
        HpkeData::Text(text.into())
    }
}

impl From<Vec<u8>> for HpkeData {
    fn from(bytes: Vec<u8>) -> Self {
        HpkeData::Bytes(bytes.into())
    }
}

/// Whether the server would read `text` as hex.
fn reads_as_hex(text: &str) -> bool {
    text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Serialize for HpkeData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            HpkeData::Bytes(bytes) => bytes.serialize(serializer),
            HpkeData::Text(text) if reads_as_hex(text.expose_secret()) => {
                SecretBytes::new(text.expose_secret().as_bytes()).serialize(serializer)
            }
            HpkeData::Text(text) => text.serialize(serializer),
        }
    }
}

/// Reads any string as [`HpkeData::Text`].
impl<'de> Deserialize<'de> for HpkeData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SecretString::deserialize(deserializer).map(HpkeData::Text)
    }
}

/// `POST /v2/hpke/keygen`: an HPKE key pair held by the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HpkeKeygenRequest {
    /// The KEM; X-Wing when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<HpkeKem>,
}

/// `POST /v2/hpke/seal`: HPKE base or PSK mode to a public key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HpkeSealRequest {
    /// The recipient's public key.
    pub recipient_public_key: Hex,
    /// What to seal.
    pub plaintext: HpkeData,
    /// The KEM of the recipient's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<HpkeKem>,
    /// The AEAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead: Option<HpkeAead>,
    /// Application context bound into the key schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<HpkeData>,
    /// Associated data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<HpkeData>,
    /// Pre-shared key (PSK mode, with `psk_id`), passed to the server as
    /// given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<SecretString>,
    /// Pre-shared key identifier, passed to the server as given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_id: Option<String>,
}

/// The answer of `POST /v2/hpke/seal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HpkeSealed {
    /// The encapsulated key.
    pub encapsulated_key: Hex,
    /// The ciphertext.
    pub ciphertext: Hex,
}

/// `POST /v2/hpke/open`: opens with a server-held HPKE key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HpkeOpenRequest {
    /// The server-held key.
    pub key_id: String,
    /// The encapsulated key.
    pub encapsulated_key: Hex,
    /// The ciphertext.
    pub ciphertext: Hex,
    /// The AEAD it was sealed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aead: Option<HpkeAead>,
    /// The `info` it was sealed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<HpkeData>,
    /// The associated data it was sealed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<HpkeData>,
    /// Pre-shared key (PSK mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<SecretString>,
    /// Pre-shared key identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_id: Option<String>,
}

/// The answer of `POST /v2/hpke/open`: the plaintext as UTF-8 text and as
/// bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HpkeOpened {
    /// The plaintext as UTF-8 text (invalid sequences become U+FFFD).
    pub plaintext: SecretString,
    /// The plaintext bytes.
    pub hex: SecretBytes,
}

#[cfg(test)]
mod tests;
