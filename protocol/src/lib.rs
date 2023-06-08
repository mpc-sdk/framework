//! Relay server protocol types, encoding and helper functions.

#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod constants;
mod error;
mod keypair;
mod protocol;

pub use error::Error;
pub use constants::*;
pub use keypair::*;
pub use protocol::*;

pub use hex;
pub use http;
pub use pem;
pub use snow;
pub use uuid;

/// Result type for the relay protocol.
pub type Result<T> = std::result::Result<T, Error>;
