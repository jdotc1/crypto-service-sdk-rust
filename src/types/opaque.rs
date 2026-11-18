// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OPAQUE (RFC 9807) registration and login, server side.
//!
//! The client half of OPAQUE (blinding, KE1 and KE3) is cryptography and
//! stays with the caller; these types carry its messages.

use serde::{Deserialize, Serialize};

use crate::{Hex, SecretBytes};

/// OPAQUE cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OpaqueSuite {
    /// P-256 with SHA-256.
    #[serde(rename = "P256-SHA256")]
    P256Sha256,
    /// ristretto255 with SHA-512.
    #[serde(rename = "ristretto255-SHA512")]
    Ristretto255Sha512,
}

/// `POST /v2/opaque/register/init`: evaluates a blinded registration
/// request. Needs credentials whose subject is `credential_identifier`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueRegisterInitRequest {
    /// The credential identifier, 1 to 256 characters.
    pub credential_identifier: String,
    /// The serialised registration request.
    pub request: Hex,
    /// The cipher suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite: Option<OpaqueSuite>,
}

/// The answer of `POST /v2/opaque/register/init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OpaqueRegisterInitResult {
    /// The serialised registration response.
    pub response: Hex,
}

/// `POST /v2/opaque/register/finish`: stores the registration record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueRegisterFinishRequest {
    /// The credential identifier.
    pub credential_identifier: String,
    /// The serialised registration record.
    pub record: Hex,
    /// The cipher suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite: Option<OpaqueSuite>,
}

/// The answer of `POST /v2/opaque/register/finish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OpaqueRegistered {
    /// The credential identifier.
    pub credential_identifier: String,
    /// `registered`.
    pub status: String,
}

/// `POST /v2/opaque/login/init`: evaluates KE1. No credentials needed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueLoginInitRequest {
    /// The credential identifier.
    pub credential_identifier: String,
    /// The serialised KE1 message.
    pub ke1: Hex,
    /// The cipher suite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite: Option<OpaqueSuite>,
}

/// The answer of `POST /v2/opaque/login/init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OpaqueLoginInitResult {
    /// The serialised KE2 message.
    pub ke2: Hex,
    /// The transient login session.
    pub session_id: String,
}

/// `POST /v2/opaque/login/finish`: verifies KE3. No credentials needed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueLoginFinishRequest {
    /// The login session from the init call.
    pub session_id: String,
    /// The serialised KE3 message.
    pub ke3: Hex,
}

/// The answer of `POST /v2/opaque/login/finish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OpaqueSession {
    /// The shared session key.
    pub session_key: SecretBytes,
}
