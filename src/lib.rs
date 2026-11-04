//! Offline public command requirements and implementation roadmap.
//!
//! This library decodes embedded data. Runtime app discovery and authority belong
//! to the platform; ambient effects belong to the executable's reviewed adapters.

#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Exact source revision inspected when the catalog was audited.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Repository URL for the inspected source.
    pub repository: String,
    /// Immutable commit identifier.
    pub revision: String,
    /// Published version, if the source had one.
    pub version: Option<String>,
}

/// A historical command spelling and public replacement requirements.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// Exact legacy command spelling, including its namespace.
    pub legacy_command: String,
    /// Historical command category.
    pub category: String,
    /// Classification as active, alias or retired in the audited CLI.
    pub legacy_state: String,
    /// Canonical historical command for an alias.
    pub alias_of: Option<String>,
    /// Public summary of the use case, excluding private implementation details.
    pub behavior: String,
    /// Required public integration surfaces.
    pub dependencies: Vec<String>,
    /// Authority and data-handling requirements for a replacement.
    pub safety_contract: String,
    /// Audit decision about replacement or omission.
    pub disposition: String,
    /// Proposed replacement spelling; not an executable capability claim.
    pub proposed_command: Option<String>,
    /// Roadmap phase containing the replacement work.
    pub phase: String,
    /// Delivery assessment at the time of the audit.
    pub implementation_status: String,
    /// Relevant support found in the inspected platform revision.
    pub day2_support: String,
    /// Work needed before the successor can be implemented.
    pub required_work: String,
    /// Platform source references supporting the support assessment.
    pub day2_evidence: Vec<String>,
}

/// Versioned public use-case inventory, never a runtime operation registry.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Version of the embedded catalog schema.
    pub schema_version: u8,
    /// Calendar date on which the inventory was audited.
    pub audited_on: String,
    /// Inspected platform revision.
    pub platform_source: Source,
    /// Definitions of the audit's classification vocabulary.
    pub definitions: BTreeMap<String, String>,
    /// Audited command spellings and their requirements.
    pub operations: Vec<Operation>,
}

/// One delivery phase with explicit prerequisites and acceptance criteria.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    /// Stable phase identifier used by command requirements.
    pub id: String,
    /// Human-readable phase title.
    pub title: String,
    /// Audited delivery status.
    pub status: String,
    /// Identifiers of phases that must precede this phase.
    pub depends_on: Vec<String>,
    /// Expected user-visible results.
    pub deliverables: Vec<String>,
    /// Required work owned by the platform.
    pub platform_work: Vec<String>,
    /// Evidence required before declaring the phase complete.
    pub acceptance: Vec<String>,
}

/// Versioned implementation roadmap in dependency order.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Roadmap {
    /// Version of the embedded roadmap schema.
    pub schema_version: u8,
    /// Delivery phases in prerequisite order.
    pub phases: Vec<Phase>,
}

/// Decode the embedded public command inventory without ambient I/O.
///
/// # Errors
///
/// Returns a decoding error if the embedded JSON does not match [`Catalog`].
pub fn catalog() -> Result<Catalog, serde_json::Error> {
    serde_json::from_str(include_str!("../catalog/legacy-cli.json"))
}

/// Decode the embedded implementation roadmap without ambient I/O.
///
/// # Errors
///
/// Returns a decoding error if the embedded JSON does not match [`Roadmap`].
pub fn roadmap() -> Result<Roadmap, serde_json::Error> {
    serde_json::from_str(include_str!("../catalog/roadmap.json"))
}
