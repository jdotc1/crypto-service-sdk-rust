// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sealed boxes, multi-recipient encryption and post-quantum streams.

use serde::{Deserialize, Serialize};

use crate::{Base64, Hex, SecretString};

/// `POST /v2/sealedbox/seal`: an anonymous X25519 sealed box.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedboxSealRequest {
    /// The recipient's 32-byte X25519 public key.
    pub recipient_public_key: Hex,
    /// The text to seal.
    pub plaintext: SecretString,
}

/// `POST /v2/sealedbox/seal-pq`: a hybrid X25519 and ML-KEM-768 sealed
/// box.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedboxSealPqRequest {
    /// The recipient's X25519 public key.
    pub x25519_public_key: Hex,
    /// The recipient's ML-KEM-768 public key.
    pub ml_kem_public_key: Hex,
    /// The text to seal.
    pub plaintext: SecretString,
}

/// `POST /v2/sealedbox/open` and `open-pq`: opens a sealed box with a
/// server-held key. The answer is the plaintext itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedboxOpenRequest {
    /// The server-held key.
    pub key_id: String,
    /// The sealed box.
    pub sealed: Base64,
}

/// What kind of key a multi-recipient recipient has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RecipientType {
    /// An X25519 key.
    #[default]
    Classical,
    /// An X25519 and ML-KEM-768 hybrid key.
    Pq,
}

/// One recipient of `POST /v2/multi-recipient/encrypt`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Recipient {
    /// The kind of key.
    #[serde(rename = "type")]
    pub kind: RecipientType,
    /// The X25519 public key.
    pub public_key: Hex,
    /// The ML-KEM-768 public key, for a `Pq` recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_kem_public_key: Option<Hex>,
}

/// `POST /v2/multi-recipient/encrypt`: one ciphertext, a wrapped key per
/// recipient.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiRecipientEncryptRequest {
    /// The text to encrypt.
    pub plaintext: SecretString,
    /// The recipients.
    pub recipients: Vec<Recipient>,
}

/// One recipient's share of a multi-recipient ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RecipientShare {
    /// `x25519` or `x25519-ml-kem-768`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The sender's ephemeral X25519 public key.
    pub ephemeral_public_key: Hex,
    /// The content key, wrapped for this recipient.
    pub wrapped_key: Base64,
    /// The ML-KEM-768 ciphertext (hybrid recipients only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_kem_ciphertext: Option<Hex>,
}

/// The answer of `POST /v2/multi-recipient/encrypt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MultiRecipientCiphertext {
    /// The ciphertext.
    pub ciphertext: Base64,
    /// One share per recipient, in order.
    pub recipients: Vec<RecipientShare>,
    /// `multi-recipient-secretbox`.
    pub algorithm: String,
}

/// `POST /v2/stream/pq-encrypt`: chunked hybrid post-quantum encryption.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamPqEncryptRequest {
    /// The recipient's 32-byte X25519 public key.
    pub x25519_public_key: Hex,
    /// The recipient's ML-KEM-768 public key.
    pub ml_kem_public_key: Hex,
    /// The text to encrypt.
    pub plaintext: SecretString,
    /// Chunk size in bytes, 64 to 1,048,576.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

/// `POST /v2/stream/pq-decrypt`: opens a stream with a server-held hybrid
/// key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamPqDecryptRequest {
    /// The server-held key.
    pub key_id: String,
    /// The stream.
    pub ciphertext: Base64,
    /// The chunk size it was written with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

/// One recipient of a multi-recipient stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamRecipient {
    /// The caller's identifier, 1 to 255 characters.
    pub recipient_id: String,
    /// The 32-byte X25519 public key.
    pub x25519_public_key: Hex,
    /// The ML-KEM-768 public key.
    pub ml_kem_public_key: Hex,
}

/// `POST /v2/stream/multi-pq-encrypt`: a hybrid post-quantum stream for
/// several recipients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamMultiPqEncryptRequest {
    /// The recipients.
    pub recipients: Vec<StreamRecipient>,
    /// The text to encrypt.
    pub plaintext: SecretString,
    /// Chunk size in bytes, 1024 to 16,777,216.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

/// The answer of `POST /v2/stream/multi-pq-encrypt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MultiPqCiphertext {
    /// The stream with its header.
    pub ciphertext: Base64,
    /// The number of recipients.
    pub recipient_count: u64,
    /// The algorithm.
    pub algorithm: String,
}

/// `POST /v2/stream/multi-pq-decrypt`: opens a multi-recipient stream with
/// a server-held hybrid key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamMultiPqDecryptRequest {
    /// The server-held key.
    pub key_id: String,
    /// The stream.
    pub ciphertext: Base64,
    /// Which recipient the key belongs to; found by trial when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_id: Option<String>,
    /// The chunk size it was written with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

/// The answer of `POST /v2/stream/multi-pq-decrypt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MultiPqPlaintext {
    /// The plaintext, as UTF-8 text.
    pub plaintext: SecretString,
    /// The recipient the key matched.
    pub recipient_id: String,
}
