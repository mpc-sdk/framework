//! Relay service websocket client using the [noise](https://noiseprotocol.org/)
//! protocol for end-to-end encryption intended for multi-party computation
//! and threshold signature applications.
//!
//! To support the web platform this client library uses
//! [web-sys](https://docs.rs/web-sys/latest/web_sys/) when
//! compiling for webassembly otherwise
//! [tokio-tunsgtenite](https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/).

#![deny(missing_docs)]

mod client;
mod error;
mod event_loop;
mod transport;

pub(crate) use client::{client_impl, client_transport_impl};
pub use event_loop::{Event, EventStream, JsonMessage};
pub use transport::{NetworkTransport, Transport};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use native::{
    NativeClient as Client, NativeEventLoop as EventLoop,
};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod web;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web::{WebClient as Client, WebEventLoop as EventLoop};

use mpc_relay_protocol::{
    hex, snow, Encoding, OpaqueMessage, ProtocolState,
    RequestMessage, SealedEnvelope, SessionId, TAGLEN,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub(crate) type Peers = Arc<RwLock<HashMap<Vec<u8>, ProtocolState>>>;
pub(crate) type Server = Arc<RwLock<Option<ProtocolState>>>;

/// Options used to create a new websocket client.
pub struct ClientOptions {
    /// Client static keypair.
    pub keypair: snow::Keypair,
    /// Public key for the server to connect to.
    pub server_public_key: Vec<u8>,
}

impl ClientOptions {
    /// Build a connection URL for the given server.
    ///
    /// This method appends the public key query string
    /// parameter necessary for connecting to the server.
    pub fn url(&self, server: &str) -> String {
        let server = server.trim_end_matches('/');
        format!(
            "{}/?public_key={}",
            server,
            hex::encode(&self.keypair.public)
        )
    }
}

pub use error::Error;

/// Result type for the relay client.
pub type Result<T> = std::result::Result<T, Error>;

/// Encrypt a message to send to a peer.
///
/// The protocol must be in transport mode.
async fn encrypt_peer_channel(
    public_key: impl AsRef<[u8]>,
    peer: &mut ProtocolState,
    payload: &[u8],
    encoding: Encoding,
    broadcast: bool,
    session_id: Option<SessionId>,
) -> Result<RequestMessage> {
    match peer {
        ProtocolState::Transport(transport) => {
            let mut contents = vec![0; payload.len() + TAGLEN];
            let length =
                transport.write_message(payload, &mut contents)?;
            let envelope = SealedEnvelope {
                length,
                encoding,
                payload: contents,
                broadcast,
            };

            let request =
                RequestMessage::Opaque(OpaqueMessage::PeerMessage {
                    public_key: public_key.as_ref().to_vec(),
                    session_id,
                    envelope,
                });

            Ok(request)
        }
        _ => Err(Error::NotTransportState),
    }
}

/// Decrypt a message received from a peer.
///
/// The protocol must be in transport mode.
async fn decrypt_peer_channel(
    peer: &mut ProtocolState,
    envelope: &SealedEnvelope,
) -> Result<Vec<u8>> {
    match peer {
        ProtocolState::Transport(transport) => {
            let mut contents = vec![0; envelope.length];
            transport.read_message(
                &envelope.payload[..envelope.length],
                &mut contents,
            )?;
            let new_length = contents.len() - TAGLEN;
            contents.truncate(new_length);
            Ok(contents)
        }
        _ => Err(Error::NotTransportState),
    }
}
