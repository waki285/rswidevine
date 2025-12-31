//! rswidevine - Rust Widevine CDM implementation.
//!
//! This crate provides:
//! - Widevine device (.wvd) parsing and export.
//! - CDM session management and license processing.
//! - PSSH parsing/generation with optional PlayReady conversion.
//! - Optional remote CDM client and HTTP serve API.
//!
//! Feature flags:
//! - `cli`: enable the CLI binary helpers.
//! - `playready`: enable PlayReady XML parsing and conversion.
//! - `remote`: enable RemoteCDM client support.
//! - `serve`: enable HTTP serve API.
//! - `chrono`: use chrono for date handling in CLI.
//! - `tracing`: enable tracing macros and subscriber.
#![allow(clippy::result_large_err)]

#[macro_use]
mod macros;

/// Core CDM implementation.
pub mod cdm;
/// Widevine device (.wvd) parsing and serialization.
pub mod device;
/// Common error types and Result alias.
pub mod error;
/// Decrypted key representation.
pub mod key;
/// PSSH parsing and conversion utilities.
pub mod pssh;
/// CDM session container.
pub mod session;
/// Shared helper utilities.
pub mod utils;

/// Remote CDM client (feature: `remote`).
#[cfg(feature = "remote")]
pub mod remotecdm;

/// HTTP serve API (feature: `serve`).
#[cfg(feature = "serve")]
pub mod serve;

// Protobuf-generated license protocol definitions (kept private).
mod rswidevine_license_protocol;

/// Protobuf-generated license protocol definitions.
pub mod license_protocol {
    pub use crate::rswidevine_license_protocol::*;
}
