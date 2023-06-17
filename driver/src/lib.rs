//! Drive MPC protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod bridge;
mod error;
mod round;

pub use bridge::{Bridge, SessionInitiator, SessionParticipant};
pub use error::Error;
pub use round::{Round, RoundBuffer, RoundMsg};

/// Round number.
pub type RoundNumber = u16;

/// Party number.
pub type PartyNumber = u16;

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "gg20")]
pub mod gg20;

#[cfg(feature = "gg20")]
pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020;

#[cfg(feature = "gg20")]
pub use curv;

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
    type Error: std::fmt::Debug;
    /// Incoming message type.
    type Incoming: From<Self::Outgoing>;
    /// Outgoing message type.
    type Outgoing: std::fmt::Debug + round::Round;
    /// Output when the protocol is completed.
    type Output;

    /// Handle an incoming message.
    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> std::result::Result<(), Self::Error>;

    /// Determine if the protocol wants to proceed.
    fn wants_to_proceed(&self) -> bool;

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
