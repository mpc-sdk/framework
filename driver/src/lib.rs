//! Drive MPC protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod bridge;
mod error;
mod round;

pub use bridge::{Bridge, BridgePhase};
pub use error::Error;
pub use round::{RoundBuffer, RoundMsg};

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "gg20")]
pub mod gg20;

use mpc_relay_protocol::SessionState;
use serde::{Deserialize, Serialize};

/// Parameters used during key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameters {
    /// Number of parties `n`.
    pub parties: u16,
    /// Threshold for signing `t`.
    ///
    /// The threshold must be crossed (`t + 1`) for signing
    /// to commence.
    pub threshold: u16,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            parties: 3,
            threshold: 1,
        }
    }
}

/// Session information for a participant.
#[derive(Clone, Debug)]
pub struct Participant {
    /// Public key of this participant.
    pub public_key: Vec<u8>,
    /// Session state.
    pub session: SessionState,
}

/// Trait for implementations that drive
/// protocol to completion.
pub trait ProtocolDriver {
    /// Error type for results.
    type Error;
    /// Incoming message type.
    type Incoming;
    /// Outgoing message type.
    type Outgoing;
    /// Output when the protocol is completed.
    type Output;

    /// Handle an incoming message.
    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> std::result::Result<(), Self::Error>;

    /// Proceed to the next round.
    fn proceed(
        &mut self,
    ) -> std::result::Result<(u16, Vec<Self::Outgoing>), Self::Error>;

    /// Complete the protocol and get the output.
    fn finish(
        &mut self,
    ) -> std::result::Result<Self::Output, Self::Error>;
}

#[cfg(feature = "gg20")]
/// Compute the address of an uncompressed public key (65 bytes).
pub(crate) fn address(public_key: &[u8]) -> String {
    use mpc_relay_protocol::hex;
    use sha3::{Digest, Keccak256};

    // Remove the leading 0x04
    let bytes = &public_key[1..];
    let digest = Keccak256::digest(bytes);
    let final_bytes = &digest[12..];
    format!("0x{}", hex::encode(final_bytes))
}
