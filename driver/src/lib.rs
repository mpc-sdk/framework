//! Drive MPC protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod bridge;
mod error;
mod round;
mod session;

pub(crate) use bridge::Bridge;
pub use error::Error;
pub(crate) use round::{Round, RoundBuffer, RoundMsg};
pub use session::{SessionInitiator, SessionParticipant};

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "gg20")]
pub mod gg20;

#[cfg(feature = "gg20")]
#[doc(hidden)]
pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020;

#[cfg(feature = "gg20")]
#[doc(hidden)]
pub use curv;

/// Trait for implementations that drive
/// protocol to completion.
pub(crate) trait ProtocolDriver {
    /// Error type for results.
    type Error: std::fmt::Debug
        + From<mpc_relay_client::Error>
        + From<Box<crate::Error>>;
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

    /*
    /// Determine if the protocol wants to proceed.
    fn wants_to_proceed(&self) -> bool;
    */

    /// Proceed to the next round.
    fn proceed(
        &mut self,
    ) -> std::result::Result<Vec<Self::Outgoing>, Self::Error>;

    /// Complete the protocol and get the output.
    fn finish(self)
        -> std::result::Result<Self::Output, Self::Error>;
}

#[cfg(feature = "gg20")]
/// Compute the address of an uncompressed public key (65 bytes).
pub(crate) fn address(public_key: &[u8]) -> String {
    use mpc_protocol::hex;
    use sha3::{Digest, Keccak256};

    // Remove the leading 0x04
    let bytes = &public_key[1..];
    let digest = Keccak256::digest(bytes);
    let final_bytes = &digest[12..];
    format!("0x{}", hex::encode(final_bytes))
}
