// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The service description, probes, the algorithm catalogue and the
//! compliance documents.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The answer of `GET /`: what the service is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ServiceInfo {
    /// A stable identifier of the service (a UUID).
    pub id: String,
    /// The service's name.
    pub title: String,
    /// What it does.
    pub description: String,
    /// More about it.
    pub details: String,
    /// The server's version.
    pub version: String,
    /// The licence.
    pub license: String,
    /// The project's URL.
    pub url: String,
}

/// The answer of `GET /health`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Health {
    /// `ok`.
    pub status: String,
    /// `200`.
    pub status_code: u16,
    /// Seconds since the process started.
    pub uptime: f64,
}

/// The answer of `GET /live`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Liveness {
    /// `alive`.
    pub status: String,
    /// Whole seconds since the process started.
    pub uptime: u64,
}

/// The checks behind `GET /ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ReadinessChecks {
    /// Whether the server is accepting requests (not draining).
    pub accepting: bool,
    /// Whether the key store is usable.
    pub key_store: bool,
    /// Checks this version does not name.
    #[serde(flatten)]
    pub other: BTreeMap<String, bool>,
}

/// The answer of `GET /ready`. A server that is not ready answers `503`,
/// which arrives as an [`Error::Api`](crate::Error::Api).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Readiness {
    /// `ready` or `not_ready`.
    pub status: String,
    /// The individual checks.
    pub checks: ReadinessChecks,
}

/// The answer of `GET /v2/algorithms`: algorithm names by category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Algorithms {
    /// Symmetric encryption.
    pub encryption: Vec<String>,
    /// Hash functions.
    pub hashing: Vec<String>,
    /// Key derivation.
    pub kdf: Vec<String>,
    /// MACs.
    pub mac: Vec<String>,
    /// Signatures.
    pub signing: Vec<String>,
    /// Key exchange.
    pub key_exchange: Vec<String>,
    /// Post-quantum algorithms.
    pub post_quantum: Vec<String>,
    /// Categories this version does not name.
    #[serde(flatten)]
    pub other: BTreeMap<String, Vec<String>>,
}

/// One algorithm and its suggested sunset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeprecationEntry {
    /// The algorithm.
    pub algorithm: String,
    /// `symmetric` or `asymmetric`.
    pub category: String,
    /// The suggested sunset date.
    pub sunset_date: String,
    /// What to move to.
    pub recommended_migration: String,
}

/// One package of the cryptographic inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct InventoryEntry {
    /// The package.
    pub package: String,
    /// Its version.
    pub version: String,
    /// `implemented`, `partial` or `placeholder`.
    pub status: String,
    /// Its FIPS status, as the server states it.
    pub fips_compliance: String,
}

/// The answer of `GET /v2/compliance/dora`: a self-reported inventory, not
/// a compliance assessment under Regulation (EU) 2022/2554.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DoraCompliance {
    /// `DORA (EU 2022/2554)`.
    pub standard: String,
    /// `Article 9 & Article 13`.
    pub article: String,
    /// The server's own summary.
    pub status: String,
    /// What the document is and is not.
    pub disclaimer: String,
    /// When it was produced (RFC 3339).
    pub timestamp: String,
    /// Primitives in use.
    pub active_primitives_count: u64,
    /// Post-quantum primitives in use.
    pub post_quantum_primitives_count: u64,
    /// The post-quantum share of the primitives.
    pub quantum_resistance_ratio: f64,
    /// The packages.
    pub cryptographic_inventory: Vec<InventoryEntry>,
    /// Suggested sunsets.
    pub algorithm_deprecation_schedule: Vec<DeprecationEntry>,
}

/// A name and value pair of a CBOM component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CbomProperty {
    /// The property name.
    pub name: String,
    /// Its value.
    pub value: String,
}

/// One component of the CBOM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CbomComponent {
    /// The component type, for example `cryptographic-asset`.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The component's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The component's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Name and value pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<CbomProperty>>,
    /// The rest of the CycloneDX component.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

/// The answer of `GET /v2/compliance/cbom`: a CycloneDX 1.6 cryptographic
/// bill of materials (`application/vnd.cyclonedx+json`), not wrapped in
/// `data`. Informational input for CRA and DORA work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Cbom {
    /// `CycloneDX`.
    pub bom_format: String,
    /// `1.6`.
    pub spec_version: String,
    /// `urn:uuid:...`.
    pub serial_number: String,
    /// The BOM version.
    pub version: u64,
    /// The CycloneDX metadata object.
    pub metadata: Map<String, Value>,
    /// The components.
    pub components: Vec<CbomComponent>,
    /// The rest of the CycloneDX document.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}
