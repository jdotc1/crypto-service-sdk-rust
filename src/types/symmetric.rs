// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AEAD, secretbox, password encryption and AES key wrap.

use serde::{Deserialize, Serialize};

use crate::{Base64, SecretBytes, SecretString};

/// `POST /v2/encrypt`: XChaCha20-Poly1305 under a caller-held key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptRequest {
    /// The 32-byte key.
    pub key: SecretBytes,
    /// The text to encrypt (1 byte to 10 MiB).
    pub plaintext: SecretString,
}

/// `POST /v2/decrypt`: opens what [`EncryptRequest`] produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecryptRequest {
    /// The 32-byte key.
    pub key: SecretBytes,
    /// `nonce || ciphertext || tag`, as the encrypt call returned it.
    pub ciphertext: Base64,
}

/// `POST /v2/secretbox/seal`: XChaCha20-Poly1305 with optional associated
/// data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretboxSealRequest {
    /// The 32-byte key.
    pub key: SecretBytes,
    /// The text to seal.
    pub plaintext: SecretString,
    /// Associated data, as UTF-8 text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// `POST /v2/secretbox/open`: opens a secretbox. The answer is the
/// plaintext itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretboxOpenRequest {
    /// The 32-byte key.
    pub key: SecretBytes,
    /// The sealed box.
    pub ciphertext: Base64,
    /// The associated data it was sealed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// `POST /v2/password/encrypt`: Argon2id key derivation and
/// XChaCha20-Poly1305.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordEncryptRequest {
    /// The password.
    pub password: SecretString,
    /// The text to encrypt.
    pub plaintext: SecretString,
}

/// The answer of `POST /v2/password/encrypt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PasswordEncryptResult {
    /// The envelope: version, Argon2id parameters, salt, nonce and
    /// ciphertext.
    pub encrypted: Base64,
    /// `argon2id-xchacha20-poly1305`.
    pub algorithm: String,
}

/// `POST /v2/password/decrypt`: opens a password envelope. The answer is
/// the plaintext itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordDecryptRequest {
    /// The password.
    pub password: SecretString,
    /// The envelope.
    pub ciphertext: Base64,
}

/// AES key wrap modes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum KeyWrapAlgorithm {
    /// AES-KW, RFC 3394 (keys of a multiple of 8 bytes).
    #[default]
    AesKw,
    /// AES-KWP, RFC 5649 (keys of any length).
    AesKwp,
}

/// `POST /v2/keys/wrap`: wraps a key under a key-encryption key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyWrapRequest {
    /// The key-encryption key (16, 24 or 32 bytes).
    pub kek: SecretBytes,
    /// The key to wrap.
    pub key_to_wrap: SecretBytes,
    /// The mode; AES-KW when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<KeyWrapAlgorithm>,
}

/// The answer of `POST /v2/keys/wrap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KeyWrapResult {
    /// The wrapped key.
    pub wrapped: Base64,
    /// The mode used.
    pub algorithm: String,
}

/// `POST /v2/keys/unwrap`: unwraps a key. The answer is the key itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyUnwrapRequest {
    /// The key-encryption key.
    pub kek: SecretBytes,
    /// The wrapped key.
    pub wrapped_key: Base64,
    /// The mode it was wrapped with; AES-KW when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<KeyWrapAlgorithm>,
}
