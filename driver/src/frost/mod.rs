//! FROST protocol implementations.
mod error;

#[cfg(feature = "frost-ed25519")]
pub mod ed25519;

pub use error::Error;

/// Result type for the FROST protocol.
pub type Result<T> = std::result::Result<T, Error>;
