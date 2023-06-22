//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use mpc_protocol::{hex, Keypair, Parameters};

/// Supported multi-party computation protocols.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Protocol {
    #[cfg(feature = "gg20")]
    /// The GG2020 protocol.
    #[serde(rename = "gg20")]
    GG20,
    #[cfg(feature = "cggmp")]
    /// The CGGMP protocol.
    #[serde(rename = "cggmp")]
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
pub enum PrivateKey {
    #[cfg(feature = "gg20")]
    /// Key share for the GG20 protocol.
    #[serde(rename = "gg20")]
    GG20(crate::gg20::KeyShare),
}

#[cfg(feature = "gg20")]
impl From<crate::gg20::KeyShare> for KeyShare {
    fn from(local_key: crate::gg20::KeyShare) -> Self {
        let public_key =
            local_key.public_key().to_bytes(false).to_vec();
        Self {
            private_key: PrivateKey::GG20(local_key),
            address: crate::address(&public_key),
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
    /// Server options.
    pub server: ServerOptions,
    /// Parameters for key generation.
    pub parameters: Parameters,
}
