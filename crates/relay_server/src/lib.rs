//! ***Moved to `polysig-relay-server`***.
//!
//! Relay websocket server using the [noise](https://noiseprotocol.org/)
//! protocol for end-to-end encryption intended for multi-party computation
//! and threshold signature applications.

#![deny(missing_docs)]

mod config;
mod error;
mod server;
mod service;
mod websocket;

pub use config::ServerConfig;
pub use error::Error;
pub use server::RelayServer;

pub use axum;

/// Result type for the relay service.
pub type Result<T> = std::result::Result<T, Error>;
