//! Internal shared types for MPC protocols.

mod round;
mod types;

pub use round::{Round, RoundMsg};
pub use types::{
    Participant, PartyOptions, ServerOptions, SessionOptions,
};

#[cfg(feature = "cggmp")]
pub use synedrion::{self, bip32, k256};

#[cfg(feature = "frost-ed25519")]
pub use frost_ed25519;

/// Information about the current found which
/// can be retrieved from a driver.
#[derive(Debug)]
pub struct RoundInfo {
    /// Whether the round is ready to be finalized.
    pub can_finalize: bool,
    /// Whether the round is an echo round.
    pub is_echo: bool,
    /// Round number.
    pub round_number: u8,
}

/// Trait for implementations that drive
/// protocol to completion.
pub trait ProtocolDriver {
    /// Error type for results.
    type Error: std::error::Error
        + std::fmt::Debug
        + Send
        + Sync
        + From<mpc_protocol::Error>
        + 'static;

    /// Outgoing message type.
    type Message: std::fmt::Debug + round::Round;

    /// Output when the protocol is completed.
    type Output;

    /// Handle an incoming message.
    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> std::result::Result<(), Self::Error>;

    /// Proceed to the next round.
    fn proceed(
        &mut self,
    ) -> std::result::Result<Vec<Self::Message>, Self::Error>;

    /// Information about the current round for the driver.
    fn round_info(
        &self,
    ) -> std::result::Result<RoundInfo, Self::Error>;

    /// Try to finalize a round if the protocol is completed
    /// the result is returned.
    ///
    /// Must check with `can_finalize()` first.
    fn try_finalize_round(
        &mut self,
    ) -> std::result::Result<Option<Self::Output>, Self::Error>;
}
