//! Relay server using the noise protocol for E2EE designed
//! for MPC/TSS applications.

#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod client;
pub mod constants;
mod error;
pub mod keypair;
mod protocol;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod server;

pub use client::{ClientOptions, Event};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use client::{EventLoop, NativeClient};

pub use error::Error;
pub(crate) use protocol::{
    decode, encode, HandshakeType, PeerMessage, ProtocolState,
    RequestMessage, ResponseMessage,
};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use server::{config::ServerConfig, RelayServer};

pub use snow;

/// Result type for the relay service.
pub type Result<T> = std::result::Result<T, Error>;
