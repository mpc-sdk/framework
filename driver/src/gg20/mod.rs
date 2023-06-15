//! Driver for the GG2020 protocol.

mod error;
pub mod keygen;
mod round;

pub use error::Error;
pub use round::RoundMsg;

/// Result type for the GG2020 protocol.
pub type Result<T> = std::result::Result<T, Error>;

