//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use mpc_relay_protocol::{Keypair, SessionId};

/// Supported multi-party computation protocols.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Protocol {
    /// The GG2020 protocol.
    #[serde(rename = "gg20")]
    GG20,
    /// The CGGMP protocol.
    #[serde(rename = "cggmp")]
    CGGMP,
}

/// Server options.
#[derive(Serialize, Deserialize)]
pub struct ServerOptions {
    /// URL for the server.
    server_url: String,
    /// Server public key.
    server_public_key: Vec<u8>,
}

/// Options used for distributed key generation.
#[derive(Serialize, Deserialize)]
pub struct KeygenOptions {
    /// MPC protocol.
    protocol: Protocol,
    /// Keypair for the participant.
    keypair: Keypair,
    /// Other participants in the session.
    participants: Vec<Vec<u8>>,
    /// Session identifier.
    session_id: SessionId,
    /// Server options.
    server: ServerOptions,
}
