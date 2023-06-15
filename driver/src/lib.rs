//! Drive MPC protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod round;

pub use round::RoundMsg;

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
    ) -> Result<(), Self::Error>;

    /// Proceed to the next round.
    fn proceed(
        &mut self,
    ) -> Result<(u16, Vec<Self::Outgoing>), Self::Error>;

    /// Complete the protocol and get the output.
    fn finish(&mut self) -> Result<Self::Output, Self::Error>;
}
