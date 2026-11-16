// SPDX-License-Identifier: Apache-2.0 OR MIT
//! KMS routes: keys held by a provider (`local`, AWS, GCP, Vault).
//!
//! KMS ciphertexts and wrapped keys are opaque provider strings, kept as
//! `String` and passed back unchanged.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::encoding::encode_hex;
use crate::{SecretBytes, SecretString};

/// What a KMS key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum KmsKeyUsage {
    /// Encryption.
    Encrypt,
    /// Signing.
    Sign,
    /// Key wrapping.
    Wrap,
}

/// `POST /v2/kms/create-key`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmsCreateKeyRequest {
    /// The provider; the server's default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The provider's algorithm name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// What the key is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<KmsKeyUsage>,
    /// Provider metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// The answer of `POST /v2/kms/create-key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KmsKey {
    /// The provider's key identifier.
    pub key_id: String,
    /// The provider.
    pub provider: String,
    /// The algorithm.
    pub algorithm: String,
    /// What the key is for.
    pub usage: String,
    /// When it was created (RFC 3339).
    pub created_at: String,
    /// Whether it is enabled.
    pub enabled: bool,
    /// The current key version, for providers that version keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
}

/// How `POST /v2/kms/encrypt` reads `plaintext`. Never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum KmsEncoding {
    /// UTF-8 text (the server's default).
    Utf8,
    /// Hex.
    Hex,
}

/// `POST /v2/kms/encrypt`. Build it with [`KmsEncryptRequest::text`] or
/// [`KmsEncryptRequest::bytes`], which set `encoding` to match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmsEncryptRequest {
    /// The provider's key identifier.
    pub key_id: String,
    /// The plaintext, encoded as `encoding` says.
    pub plaintext: SecretString,
    /// How `plaintext` is encoded; UTF-8 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<KmsEncoding>,
    /// The provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Encryption context, bound to the ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

impl KmsEncryptRequest {
    /// Encrypts the UTF-8 bytes of `text` under `key_id`.
    pub fn text(key_id: impl Into<String>, text: impl Into<SecretString>) -> Self {
        KmsEncryptRequest {
            key_id: key_id.into(),
            plaintext: text.into(),
            ..Self::default()
        }
    }

    /// Encrypts `bytes` under `key_id`, sent as hex with `encoding: hex`.
    pub fn bytes(key_id: impl Into<String>, bytes: &[u8]) -> Self {
        KmsEncryptRequest {
            key_id: key_id.into(),
            plaintext: SecretString::new(encode_hex(bytes)),
            encoding: Some(KmsEncoding::Hex),
            ..Self::default()
        }
    }
}

/// The answer of `POST /v2/kms/encrypt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KmsCiphertext {
    /// The provider's ciphertext, opaque.
    pub ciphertext: String,
    /// The key used.
    pub key_id: String,
    /// The provider.
    pub provider: String,
    /// The key version used, for providers that version keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u64>,
    /// The encryption context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

/// `POST /v2/kms/decrypt`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmsDecryptRequest {
    /// The provider's key identifier.
    pub key_id: String,
    /// The ciphertext, as the encrypt call returned it.
    pub ciphertext: String,
    /// The provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The encryption context it was encrypted with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

/// The answer of `POST /v2/kms/decrypt`: the plaintext as UTF-8 text and
/// as bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KmsPlaintext {
    /// The plaintext as UTF-8 text (invalid sequences become U+FFFD).
    pub plaintext: SecretString,
    /// The plaintext bytes.
    pub hex: SecretBytes,
    /// The key used.
    pub key_id: String,
    /// The provider.
    pub provider: String,
}

/// `POST /v2/kms/generate-data-key`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmsGenerateDataKeyRequest {
    /// The provider's key identifier.
    pub key_id: String,
    /// The data key's specification, as the provider names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_spec: Option<String>,
    /// The provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// The answer of `POST /v2/kms/generate-data-key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KmsDataKey {
    /// The data key bytes; use, then drop.
    pub plaintext: SecretBytes,
    /// The data key, encrypted under the KMS key: keep this one.
    pub ciphertext: String,
    /// The key used.
    pub key_id: String,
    /// The provider.
    pub provider: String,
}

/// `POST /v2/kms/wrap`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmsWrapRequest {
    /// The provider's key identifier.
    pub key_id: String,
    /// The key bytes to wrap.
    pub unwrapped_key: SecretBytes,
    /// The provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The encryption context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

/// The answer of `POST /v2/kms/wrap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KmsWrapped {
    /// The wrapped key, opaque.
    pub wrapped_key: String,
    /// The key used.
    pub key_id: String,
    /// The provider.
    pub provider: String,
}

/// `POST /v2/kms/unwrap`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KmsUnwrapRequest {
    /// The provider's key identifier.
    pub key_id: String,
    /// The wrapped key, as the wrap call returned it.
    pub wrapped_key: String,
    /// The provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The encryption context it was wrapped with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

/// The answer of `POST /v2/kms/unwrap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KmsUnwrapped {
    /// The key bytes.
    pub unwrapped_key: SecretBytes,
    /// The key used.
    pub key_id: String,
    /// The provider.
    pub provider: String,
}
