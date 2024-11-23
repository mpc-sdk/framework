//! Meeting room websocket server.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod meeting_manager;
mod server;
mod websocket;

pub use config::ServerConfig;
pub use error::Error;
pub use server::MeetingServer;

pub use axum;

/// Result type for the meeting service.
pub type Result<T> = std::result::Result<T, Error>;
