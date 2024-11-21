//! Meeting room websocket server.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod server;
mod service;
mod websocket;

pub use config::ServerConfig;
pub use error::Error;
pub use server::MeetingServer;

pub use axum;

/// Result type for the meeting service.
pub type Result<T> = std::result::Result<T, Error>;
