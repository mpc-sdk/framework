//! Node bindings for the polysig library.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Threshold signature protocols.
#[cfg(any(feature = "cggmp", feature = "frost-ed25519"))]
pub mod protocols;

/// Single party signers.
pub mod signers;
