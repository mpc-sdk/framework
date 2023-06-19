//! Driver for the GG2020 protocol.

mod error;
mod keygen;
mod sign;

pub use error::Error;
pub use keygen::{KeyGenDriver, KeyShare};
pub use sign::{
    OfflineResult, ParticipantDriver, PreSignDriver, Signature,
    SignatureDriver,
};

/// Result type for the GG2020 protocol.
pub type Result<T> = std::result::Result<T, Error>;
