//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use mpc_driver::gg20;
use mpc_protocol::{Keypair, Parameters, SessionId, hex};

/// Supported multi-party computation protocols.
#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum Protocol {
    /// The GG2020 protocol.
    GG20,
    /// The CGGMP protocol.
    CGGMP,
}

/// Generated key share.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyShare {
    /// Private key share information.
    pub private_key: PrivateKey,
    /// The public key.
    pub public_key: Vec<u8>,
    /// Address generated from the public key.
    pub address: String,
}

/// Key share variants by protocol.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrivateKey {
    /// Key share for the GG20 protocol.
    GG20(gg20::KeyShare),
}

impl From<gg20::KeyShare> for KeyShare {
    fn from(local_key: gg20::KeyShare) -> Self {
        let public_key =
            local_key.public_key().to_bytes(false).to_vec();
        Self {
            private_key: PrivateKey::GG20(local_key),
            address: mpc_driver::address(&public_key),
            public_key,
        }
    }
}

/// Server options.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOptions {
    /// URL for the server.
    pub server_url: String,
    /// Server public key.
    #[serde(with = "hex::serde")]
    pub server_public_key: Vec<u8>,
}

/// Options used for distributed key generation.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOptions {
    /// MPC protocol.
    pub protocol: Protocol,
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Session identifier.
    pub session_id: SessionId,
    /// Server options.
    pub server: ServerOptions,
    /// Parameters for key generation.
    pub parameters: Parameters,
}
