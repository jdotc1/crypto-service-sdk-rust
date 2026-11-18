// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ML-KEM, the hybrid KEM, ML-DSA, SLH-DSA and ISO 20022 dual signatures.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Hex, SecretBytes, SecretString};

/// `POST /v2/pq/encapsulate`: a shared secret for an ML-KEM-768 public
/// key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlKemEncapsulateRequest {
    /// The 1184-byte ML-KEM-768 public key.
    pub public_key: Hex,
}

/// The answer of `POST /v2/pq/encapsulate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MlKemEncapsulation {
    /// The 1088-byte ciphertext, for the key's holder.
    pub ciphertext: Hex,
    /// The 32-byte shared secret.
    pub shared_secret: SecretBytes,
    /// `ml-kem-768`.
    pub algorithm: String,
}

/// `POST /v2/pq/decapsulate`: the shared secret, with a server-held
/// ML-KEM-768 key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlKemDecapsulateRequest {
    /// The server-held key.
    pub key_id: String,
    /// The ciphertext.
    pub ciphertext: Hex,
}

/// A shared secret from a decapsulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SharedSecret {
    /// The 32-byte shared secret.
    pub shared_secret: SecretBytes,
    /// The algorithm.
    pub algorithm: String,
    /// The combiner of a hybrid KEM (`crypto-service/hybrid-kem/v2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combiner: Option<String>,
}

/// The answer of `POST /v2/pq/hybrid/keygen`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HybridKeyPair {
    /// The key's identifier.
    pub key_id: String,
    /// The 32-byte X25519 public key.
    pub x25519_public_key: Hex,
    /// The 1184-byte ML-KEM-768 public key.
    pub ml_kem_public_key: Hex,
    /// `x25519-ml-kem-768`.
    pub algorithm: String,
}

/// `POST /v2/pq/hybrid/encapsulate`: X25519 and ML-KEM-768 to a hybrid
/// public key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HybridEncapsulateRequest {
    /// The 32-byte X25519 public key.
    pub x25519_public_key: Hex,
    /// The ML-KEM-768 public key.
    pub ml_kem_public_key: Hex,
}

/// The answer of `POST /v2/pq/hybrid/encapsulate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HybridEncapsulation {
    /// The 32-byte ephemeral X25519 public key.
    pub x25519_ephemeral_public: Hex,
    /// The 1088-byte ML-KEM-768 ciphertext.
    pub ml_kem_ciphertext: Hex,
    /// The combined 32-byte shared secret.
    pub shared_secret: SecretBytes,
    /// `x25519-ml-kem-768`.
    pub algorithm: String,
    /// `crypto-service/hybrid-kem/v2`.
    pub combiner: String,
}

/// `POST /v2/pq/hybrid/decapsulate`: the combined shared secret, with a
/// server-held hybrid key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HybridDecapsulateRequest {
    /// The server-held key.
    pub key_id: String,
    /// The sender's 32-byte ephemeral X25519 public key.
    pub x25519_ephemeral_public: Hex,
    /// The ML-KEM-768 ciphertext.
    pub ml_kem_ciphertext: Hex,
}

/// ML-DSA security levels (FIPS 204).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[non_exhaustive]
pub enum MlDsaLevel {
    /// ML-DSA-44.
    #[default]
    L44,
    /// ML-DSA-65.
    L65,
    /// ML-DSA-87.
    L87,
}

impl From<MlDsaLevel> for u8 {
    fn from(level: MlDsaLevel) -> u8 {
        match level {
            MlDsaLevel::L44 => 44,
            MlDsaLevel::L65 => 65,
            MlDsaLevel::L87 => 87,
        }
    }
}

impl TryFrom<u8> for MlDsaLevel {
    type Error = &'static str;

    fn try_from(level: u8) -> Result<Self, Self::Error> {
        match level {
            44 => Ok(MlDsaLevel::L44),
            65 => Ok(MlDsaLevel::L65),
            87 => Ok(MlDsaLevel::L87),
            _ => Err("an ML-DSA level is 44, 65 or 87"),
        }
    }
}

/// `POST /v2/pq/dsa/keygen`: an ML-DSA key pair held by the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlDsaKeygenRequest {
    /// The level.
    pub level: MlDsaLevel,
}

/// `POST /v2/pq/dsa/verify`: an ML-DSA signature against a public key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlDsaVerifyRequest {
    /// The level of the key.
    pub level: MlDsaLevel,
    /// The public key.
    pub public_key: Hex,
    /// The signed text.
    pub message: SecretString,
    /// The signature.
    pub signature: Hex,
}

/// SLH-DSA parameter sets (FIPS 205).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum SlhDsaVariant {
    #[default]
    #[serde(rename = "sha2-128f")]
    Sha2_128f,
    #[serde(rename = "sha2-128s")]
    Sha2_128s,
    #[serde(rename = "sha2-192f")]
    Sha2_192f,
    #[serde(rename = "sha2-192s")]
    Sha2_192s,
    #[serde(rename = "sha2-256f")]
    Sha2_256f,
    #[serde(rename = "sha2-256s")]
    Sha2_256s,
    #[serde(rename = "shake-128f")]
    Shake128f,
    #[serde(rename = "shake-128s")]
    Shake128s,
    #[serde(rename = "shake-192f")]
    Shake192f,
    #[serde(rename = "shake-192s")]
    Shake192s,
    #[serde(rename = "shake-256f")]
    Shake256f,
    #[serde(rename = "shake-256s")]
    Shake256s,
}

/// `POST /v2/pq/slh-dsa/keygen`: an SLH-DSA key pair held by the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlhDsaKeygenRequest {
    /// The parameter set.
    pub variant: SlhDsaVariant,
}

/// `POST /v2/pq/slh-dsa/verify`: an SLH-DSA signature against a public
/// key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SlhDsaVerifyRequest {
    /// The parameter set of the key.
    pub variant: SlhDsaVariant,
    /// The public key.
    pub public_key: Hex,
    /// The signed text.
    pub message: SecretString,
    /// The signature.
    pub signature: Hex,
}

/// One signature of an ISO 20022 envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeSignature {
    /// The algorithm: `ed25519` for the classical one, `ml-dsa-44`,
    /// `ml-dsa-65` or `ml-dsa-87` for the post-quantum one.
    pub algorithm: String,
    /// The signer's public key, as the envelope states it.
    pub public_key: Hex,
    /// The signature.
    pub signature: Hex,
}

/// A dual-signed ISO 20022 envelope, as crypto-lib writes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Iso20022Envelope {
    /// The message identifier.
    pub message_id: String,
    /// `pacs.008`, `pain.001`, `camt.053` or `generic`.
    pub message_type: String,
    /// The payload's digest.
    pub payload_digest: Hex,
    /// `sha256`, `sha384` or `sha512`.
    pub digest_algorithm: String,
    /// When it was signed, as written.
    pub timestamp: String,
    /// The Ed25519 signature.
    pub classical: EnvelopeSignature,
    /// The ML-DSA signature.
    pub post_quantum: EnvelopeSignature,
}

/// The signer's public keys, as the caller trusts them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedKeys {
    /// The Ed25519 public key.
    pub classical_public_key: Hex,
    /// The ML-DSA public key.
    pub post_quantum_public_key: Hex,
}

/// `POST /v2/stream/iso20022`: checks an envelope's digest and both
/// signatures against `trusted_keys`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Iso20022VerifyRequest {
    /// The payload the envelope signs, as JSON.
    pub payload: Value,
    /// The envelope.
    pub envelope: Iso20022Envelope,
    /// The keys to check the signatures against.
    pub trusted_keys: TrustedKeys,
}

/// The answer of `POST /v2/stream/iso20022`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
// The server answers these four flags; the struct mirrors it.
#[allow(clippy::struct_excessive_bools)]
pub struct Iso20022Verification {
    /// Whether the digest and both signatures hold.
    pub valid: bool,
    /// The envelope's message identifier.
    pub message_id: String,
    /// Whether the payload matches the digest.
    pub digest_matches: bool,
    /// Whether the Ed25519 signature holds.
    pub classical_valid: bool,
    /// Whether the ML-DSA signature holds.
    pub post_quantum_valid: bool,
}
