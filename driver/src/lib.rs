//! Drive multi-party computation protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
pub mod signers;

mod error;

#[cfg(any(feature = "ecdsa", feature = "cggmp"))]
pub mod recoverable_signature;

#[cfg(feature = "cggmp")]
pub mod meeting;

#[cfg(feature = "cggmp")]
mod protocol;

#[cfg(feature = "cggmp")]
pub use protocol::*;

pub use error::Error;

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "cggmp")]
pub mod cggmp;

pub use sha3;
