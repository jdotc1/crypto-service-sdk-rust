// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Hashing, MACs, key derivation and password hashing.

use serde::{Deserialize, Serialize};

use crate::{Hex, SecretBytes, SecretString};

/// Hash algorithms of `POST /v2/hash`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256.
    #[default]
    #[serde(rename = "sha256")]
    Sha256,
    /// SHA-384.
    #[serde(rename = "sha384")]
    Sha384,
    /// SHA-512.
    #[serde(rename = "sha512")]
    Sha512,
    /// SHA3-256.
    #[serde(rename = "sha3-256")]
    Sha3_256,
    /// SHA3-512.
    #[serde(rename = "sha3-512")]
    Sha3_512,
    /// BLAKE2b-512.
    #[serde(rename = "blake2b")]
    Blake2b,
    /// BLAKE3.
    #[serde(rename = "blake3")]
    Blake3,
}

/// HMAC hash functions of `POST /v2/hmac` and `POST /v2/hmac/verify`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MacAlgorithm {
    /// HMAC-SHA-256.
    #[default]
    #[serde(rename = "sha256")]
    Sha256,
    /// HMAC-SHA-384.
    #[serde(rename = "sha384")]
    Sha384,
    /// HMAC-SHA-512.
    #[serde(rename = "sha512")]
    Sha512,
    /// HMAC-SHA3-256.
    #[serde(rename = "sha3-256")]
    Sha3_256,
    /// HMAC-SHA3-512.
    #[serde(rename = "sha3-512")]
    Sha3_512,
}

/// `POST /v2/hash`: the digest of the UTF-8 bytes of `data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HashRequest {
    /// The hash function.
    pub algorithm: HashAlgorithm,
    /// The text to hash (1 byte to 10 MiB).
    pub data: SecretString,
}

/// The answer of `POST /v2/hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct HashResult {
    /// The digest.
    pub digest: Hex,
    /// The hash function.
    pub algorithm: String,
    /// The digest length in bytes.
    pub length: u64,
}

/// `POST /v2/hmac`: the HMAC of the UTF-8 bytes of `data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacRequest {
    /// The hash function.
    pub algorithm: MacAlgorithm,
    /// The text to authenticate.
    pub data: SecretString,
    /// The key, at least 16 bytes.
    pub key: SecretBytes,
}

/// The answer of `POST /v2/hmac`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MacResult {
    /// The tag.
    pub mac: Hex,
    /// The hash function.
    pub algorithm: String,
}

/// `POST /v2/hmac/verify`: whether `mac` is the HMAC of `data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacVerifyRequest {
    /// The hash function.
    pub algorithm: MacAlgorithm,
    /// The text that was authenticated.
    pub data: SecretString,
    /// The key.
    pub key: SecretBytes,
    /// The tag to check.
    pub mac: Hex,
}

/// Key derivation functions of `POST /v2/kdf`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum KdfAlgorithm {
    /// scrypt (N = 2^17, r = 8).
    Scrypt,
    /// HKDF-SHA256.
    #[default]
    HkdfSha256,
    /// PBKDF2-SHA256, at least 600,000 iterations.
    Pbkdf2Sha256,
}

/// Tuning of `POST /v2/kdf`; each member applies to some algorithms only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// scrypt's cost, 131072 (2^17).
    #[serde(rename = "N", default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u64>,
    /// scrypt's block size, 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r: Option<u32>,
    /// scrypt's parallelism, 1 to 4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
    /// PBKDF2's iteration count, 600,000 to 1,000,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    /// HKDF's info text, up to 1024 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
}

/// `POST /v2/kdf`: derives a key from a password or input key material.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KdfRequest {
    /// The derivation function.
    pub algorithm: KdfAlgorithm,
    /// The password or input key material, as text.
    pub password: SecretString,
    /// The salt; 16 random bytes when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<Hex>,
    /// The derived key's length in bytes, 16 to 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_length: Option<u32>,
    /// Algorithm parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<KdfParams>,
}

/// The answer of `POST /v2/kdf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KdfResult {
    /// The derived key.
    pub derived_key: SecretBytes,
    /// The salt used: the request's, or 16 random bytes.
    pub salt: Hex,
    /// The derivation function.
    pub algorithm: String,
    /// The derived key's length in bytes.
    pub key_length: u64,
}

/// Argon2id parameters: memory in KiB, passes and lanes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m: u32,
    /// Time cost (passes).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

/// `POST /v2/password/hash`: an Argon2id hash of a password.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordHashRequest {
    /// The password, 1 to 1024 characters.
    pub password: SecretString,
    /// Passes, 2 to 10 (default 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_cost: Option<u32>,
    /// Memory in KiB, 19456 to 262144 (default 65536).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_cost: Option<u32>,
    /// Lanes, 1 to 8 (default 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
}

/// The answer of `POST /v2/password/hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PasswordHashResult {
    /// The 32-byte Argon2id hash.
    pub hash: Hex,
    /// The random 16-byte salt.
    pub salt: Hex,
    /// The parameters used.
    pub params: Argon2Params,
    /// `argon2id`.
    pub algorithm: String,
    /// The same hash as a PHC string.
    pub phc: String,
}

/// `POST /v2/password/verify`: whether `password` matches a stored hash.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordVerifyRequest {
    /// The password to check.
    pub password: SecretString,
    /// The stored hash.
    pub hash: Hex,
    /// The stored salt.
    pub salt: Hex,
    /// The stored parameters.
    pub params: Argon2Params,
}

/// The answer of `POST /v2/password/verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PasswordVerifyResult {
    /// Whether the password matches.
    pub valid: bool,
}
