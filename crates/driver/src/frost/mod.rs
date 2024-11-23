//! FROST protocol implementations.
mod error;

#[cfg(feature = "frost")]
pub mod core;

#[cfg(feature = "frost-ed25519")]
pub mod ed25519;

pub use error::Error;

/// Result type for the FROST protocol.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const ROUND_1: u8 = 1;
pub(crate) const ROUND_2: u8 = 2;
pub(crate) const ROUND_3: u8 = 3;
