//! Relay service protocol types, encoding and helper functions.
//!
//! # Size Limitations
//!
//! The maximum size of a [noise protocol](https://noiseprotocol.org/)
//! message is 65535 and we further limit the size of buffers
//! for encoding to 32KB.
#![deny(missing_docs)]

#[doc(hidden)]
pub mod channel;
mod constants;
pub(crate) mod encoding;
mod error;
mod keypair;
mod protocol;

pub use constants::*;
pub use encoding::{decode, encode, VERSION};
pub use error::Error;
pub use keypair::*;
pub use protocol::*;

pub use hex;
pub use http;
pub use pem;
pub use snow;
pub use uuid;

/// Result type for the relay protocol.
pub type Result<T> = std::result::Result<T, Error>;
