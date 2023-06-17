//! Driver for the GG2020 protocol.

mod error;
mod keygen;
//mod sign;

pub use error::Error;
pub use keygen::KeyGenerator;

/// Result type for the GG2020 protocol.
pub type Result<T> = std::result::Result<T, Error>;
