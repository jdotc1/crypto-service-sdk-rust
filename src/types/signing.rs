// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server-held keys, Ed25519 signing and batch signing.

use serde::{Deserialize, Serialize};

use crate::{Hex, SecretBytes, SecretString};

/// Key pair algorithms of `POST /v2/keys/generate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// Ed25519 signing.
    #[default]
    Ed25519,
    /// X25519 key agreement.
    X25519,
    /// Ed448 signing.
    Ed448,
    /// X448 key agreement.
    X448,
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// ML-KEM-512.
    #[serde(rename = "ml-kem-512")]
    MlKem512,
    /// ML-KEM-768.
    #[serde(rename = "ml-kem-768")]
    MlKem768,
    /// ML-KEM-1024.
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,
    /// ML-DSA-44.
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA-65.
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// ML-DSA-87.
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
}

/// What a key is for (JWK `use`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum KeyUse {
    /// Signing.
    Sig,
    /// Encryption.
    Enc,
}

/// Metadata recorded with a generated key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMetadata {
    /// A key identifier of the caller's choosing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// What the key is for.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,
    /// An expiry, as the caller writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// `POST /v2/keys/generate`: a key pair whose private key stays on the
/// server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateKeyPairRequest {
    /// The algorithm; Ed25519 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<KeyAlgorithm>,
    /// Metadata to record with the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<KeyMetadata>,
}

/// The metadata the server recorded with a key; `kid` is always set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecordedKeyMetadata {
    /// The key identifier: the caller's, or one the server chose.
    pub kid: String,
    /// What the key is for.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    /// The expiry the caller gave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// The answer of `POST /v2/keys/generate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct GeneratedKeyPair {
    /// The key's identifier, for the signing and decryption calls.
    pub key_id: String,
    /// The algorithm.
    pub algorithm: String,
    /// The public key.
    pub public_key: Hex,
    /// The key identifier recorded in the metadata.
    pub kid: String,
    /// The recorded metadata.
    pub metadata: RecordedKeyMetadata,
}

/// The answer of `POST /v2/keys/export`: the key pair's private parts.
/// Which members are present depends on the algorithm. A member this
/// version does not name is dropped rather than kept, since it could hold
/// key material that `Debug` would then print.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ExportedKey {
    /// The key's identifier.
    pub key_id: String,
    /// The algorithm.
    pub algorithm: String,
    /// The public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Hex>,
    /// The private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<SecretBytes>,
    /// The secret key (ML-KEM, ML-DSA, SLH-DSA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<SecretBytes>,
    /// The X25519 public key of a hybrid key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x25519_public_key: Option<Hex>,
    /// The X25519 private key of a hybrid key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x25519_private_key: Option<SecretBytes>,
    /// The ML-KEM public key of a hybrid key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_kem_public_key: Option<Hex>,
    /// The ML-KEM secret key of a hybrid key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_kem_secret_key: Option<SecretBytes>,
}

/// The answer of `POST /v2/keys/delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeletedKey {
    /// `true`.
    pub deleted: bool,
    /// The deleted key's identifier.
    pub key_id: String,
}

/// `POST /v2/sign` (Ed25519) and the ML-DSA and SLH-DSA sign calls: signs
/// the UTF-8 bytes of `message` with a server-held key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignRequest {
    /// The key's identifier.
    pub key_id: String,
    /// The text to sign.
    pub message: SecretString,
}

/// `POST /v2/verify`: an Ed25519 signature against a public key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyRequest {
    /// The signed text.
    pub message: SecretString,
    /// The 32-byte public key.
    pub public_key: Hex,
    /// The 64-byte signature.
    pub signature: Hex,
}

/// One message of a batch sign.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamSignItem {
    /// The caller's identifier for this item.
    pub id: String,
    /// The server-held Ed25519 key.
    pub key_id: String,
    /// The text to sign.
    pub message: SecretString,
}

/// `POST /v2/stream/sign`: Ed25519 signatures over many messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamSignRequest {
    /// The messages.
    pub items: Vec<StreamSignItem>,
}

/// One signature of a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StreamSignature {
    /// The item's identifier.
    pub id: String,
    /// The signature.
    pub signature: Hex,
    /// `ed25519`.
    pub algorithm: String,
}

/// The answer of `POST /v2/stream/sign`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StreamSignResult {
    /// One signature per item, in order.
    pub signatures: Vec<StreamSignature>,
    /// The number of signatures.
    pub count: u64,
}

/// One signature to check in a batch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamVerifyItem {
    /// The caller's identifier for this item.
    pub id: String,
    /// The signed text.
    pub message: SecretString,
    /// The 64-byte signature.
    pub signature: Hex,
    /// The 32-byte Ed25519 public key.
    pub public_key: Hex,
}

/// `POST /v2/stream/verify`: checks many Ed25519 signatures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamVerifyRequest {
    /// The signatures.
    pub items: Vec<StreamVerifyItem>,
}

/// One outcome of a batch verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StreamVerification {
    /// The item's identifier.
    pub id: String,
    /// Whether it verified.
    pub valid: bool,
}

/// The answer of `POST /v2/stream/verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StreamVerifyResult {
    /// One outcome per item, in order.
    pub results: Vec<StreamVerification>,
    /// The number of items.
    pub count: u64,
    /// The number that verified.
    pub valid_count: u64,
    /// Whether every item verified.
    pub all_valid: bool,
}
