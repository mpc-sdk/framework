//! Relay client using the noise protocol for E2EE designed
//! for MPC/TSS applications.

#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod error;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use native::{EventLoop, NativeClient, Notification};

use mpc_relay_protocol::{snow, SessionResponse};

/// Events dispatched by the client.
#[derive(Debug)]
pub enum Event {
    /// Event dispatched when a handshake with the server
    /// is completed.
    ServerConnected {
        /// Public key of the server.
        server_key: Vec<u8>,
    },
    /// Event dispatched when a handshake with a peer
    /// has been completed.
    PeerConnected {
        /// Public key of the peer.
        peer_key: Vec<u8>,
    },
    /// Binary message received from a peer.
    BinaryMessage {
        /// Public key of the peer.
        peer_key: Vec<u8>,
        /// Message buffer.
        message: Vec<u8>,
    },
    /// JSON message received from a peer.
    JsonMessage {
        /// Public key of the peer.
        peer_key: Vec<u8>,
        /// JSON message.
        message: JsonMessage,
    },
    /// Event dispatched when a session has been created.
    SessionCreated(SessionResponse),

    /// Event dispatched when a session is ready.
    ///
    /// A session is ready when all participants
    /// have completed the server handshake.
    ///
    /// Peers can now race to handshake with each other.
    SessionReady(SessionResponse),
}

/// JSON message received from a peer.
#[derive(Debug)]
pub struct JsonMessage {
    contents: Vec<u8>,
}

impl JsonMessage {
    /// Deserialize this message.
    pub fn deserialize<'a, T: serde::de::Deserialize<'a>>(
        &'a self,
    ) -> Result<T> {
        Ok(serde_json::from_slice::<T>(&self.contents)?)
    }
}

/// Options used to create a new websocket client.
pub struct ClientOptions {
    /// Client static keypair.
    pub keypair: snow::Keypair,
    /// Public key for the server to connect to.
    pub server_public_key: Vec<u8>,
}

pub use error::Error;

/// Result type for the relay client.
pub type Result<T> = std::result::Result<T, Error>;
