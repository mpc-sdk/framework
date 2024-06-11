//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use crate::{k256::ecdsa, synedrion::RecoverableSignature};
use mpc_protocol::{hex, Keypair, Parameters};

/// Supported multi-party computation protocols.
#[derive(Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// The CGGMP protocol.
    #[cfg(feature = "cggmp")]
    Cggmp,
}

/// Signature for different protocols.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Signature {
    /// Signature for the CGGMP protocol.
    ///
    /// Note that we must convert the `RecoveryId` to `u8`
    /// for serde support.
    #[cfg(feature = "cggmp")]
    Cggmp(ecdsa::Signature, u8),
}

#[cfg(feature = "cggmp")]
impl From<RecoverableSignature> for Signature {
    fn from(value: RecoverableSignature) -> Self {
        let (sig, recovery_id) = value.to_backend();
        Signature::Cggmp(sig, recovery_id.into())
    }
}

/// Generated key share.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyShare {
    /// Private key share information.
    pub private_key: PrivateKey,
    /// The public key.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// Address generated from the public key.
    pub address: String,
}

/// Key share variants by protocol.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateKey {
    /// Key share for the CGGMP protocol.
    #[cfg(all(feature = "cggmp", not(debug_assertions)))]
    Cggmp(crate::cggmp::KeyShare<crate::synedrion::ProductionParams>),
    /// Key share for the CGGMP protocol.
    #[cfg(all(feature = "cggmp", debug_assertions))]
    Cggmp(crate::cggmp::KeyShare<crate::synedrion::TestParams>),
}

#[cfg(all(feature = "cggmp", debug_assertions))]
impl From<crate::cggmp::KeyShare<crate::synedrion::TestParams>>
    for KeyShare
{
    fn from(
        local_key: crate::cggmp::KeyShare<
            crate::synedrion::TestParams,
        >,
    ) -> Self {
        let public_key = local_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Self {
            private_key: PrivateKey::Cggmp(local_key),
            address: crate::address(&public_key),
            public_key,
        }
    }
}

#[cfg(all(feature = "cggmp", not(debug_assertions)))]
impl From<crate::cggmp::KeyShare<crate::synedrion::ProductionParams>>
    for KeyShare
{
    fn from(
        local_key: crate::cggmp::KeyShare<
            crate::synedrion::ProductionParams,
        >,
    ) -> Self {
        let public_key = local_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Self {
            private_key: PrivateKey::Cggmp(local_key),
            address: crate::address(&public_key),
            public_key,
        }
    }
}

/// Options for creating or joining a meeting point.
#[derive(Serialize, Deserialize)]
pub struct MeetingOptions {
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Server options.
    pub server: ServerOptions,
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
    /// Noise parameters pattern.
    pub pattern: Option<String>,
}

/// Options used to drive a session to completion.
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
