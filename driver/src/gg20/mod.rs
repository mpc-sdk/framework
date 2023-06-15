//! Driver for the GG2020 protocol.

mod error;
pub mod keygen;
pub mod sign;

pub use error::Error;

/// Result type for the GG2020 protocol.
pub type Result<T> = std::result::Result<T, Error>;
