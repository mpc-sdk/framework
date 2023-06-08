//! Relay server using the noise protocol for E2EE designed
//! for MPC/TSS applications.

#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

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
