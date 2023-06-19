//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use mpc_protocol::{Keypair, SessionId, Parameters};
use mpc_driver::gg20;

/// Supported multi-party computation protocols.
#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Protocol {
    /// The GG2020 protocol.
    #[serde(rename = "gg20")]
    GG20,
    /// The CGGMP protocol.
    #[serde(rename = "cggmp")]
    CGGMP,
}

/// Generated key share.
#[derive(Serialize, Deserialize)]
pub struct KeyShare {
    /// Private key share information.
    pub local_key: LocalKey,
}

/// Key share variants by protocol.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum LocalKey {
    /// Key share for the GG20 protocol.
    GG20(gg20::KeyShare),
}

/// Server options.
#[derive(Serialize, Deserialize)]
pub struct ServerOptions {
    /// URL for the server.
    pub server_url: String,
    /// Server public key.
    pub server_public_key: Vec<u8>,
}

/// Options used for distributed key generation.
#[derive(Serialize, Deserialize)]
pub struct KeygenOptions {
    /// MPC protocol.
    pub protocol: Protocol,
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Other participants in the session.
    pub participants: Vec<Vec<u8>>,
    /// Session identifier.
    pub session_id: SessionId,
    /// Server options.
    pub server: ServerOptions,
    /// Parameters for key generation.
    pub parameters: Parameters,
}
