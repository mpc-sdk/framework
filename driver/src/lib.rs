//! Drive multi-party computation protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
use async_trait::async_trait;
use mpc_client::{
    Client, ClientOptions, Event, EventLoop, Transport,
};
use mpc_protocol::hex;
use std::collections::BTreeSet;

mod bridge;
mod error;
pub mod meeting;
mod round;
mod session;
mod types;

pub(crate) use bridge::Bridge;
pub use bridge::{
    wait_for_close, wait_for_driver, wait_for_session_finish,
};
pub use error::Error;
pub(crate) use round::{Round, RoundMsg};
pub use session::{
    wait_for_session, SessionEventHandler, SessionHandler,
    SessionInitiator, SessionParticipant,
};
pub use types::*;

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "cggmp")]
pub mod cggmp;
#[cfg(feature = "cggmp")]
pub use synedrion::{self, k256};

#[cfg(feature = "cggmp")]
use synedrion::{
    k256::ecdsa::{SigningKey, VerifyingKey},
    PrehashedMessage, SessionId,
};

/// Information about the current found which
/// can be retrieved from a driver.
pub struct RoundInfo {
    /// Whether the round is ready to be finalized.
    pub can_finalize: bool,
    /// Whether the round is an echo round.
    pub is_echo: bool,
    /// Round number.
    pub round_number: u8,
}

/// Drives a protocol to completion bridging between
/// the network transport and local computation.
#[async_trait]
pub trait Driver {
    /// Error type.
    type Error: std::fmt::Debug + From<mpc_client::Error>;

    /// Output yielded when the driver completes.
    type Output;

    /// Handle an incoming event.
    async fn handle_event(
        &mut self,
        event: Event,
    ) -> std::result::Result<Option<Self::Output>, Self::Error>;

    /// Start running the protocol.
    async fn execute(
        &mut self,
    ) -> std::result::Result<(), Self::Error>;

    /// Consume this driver into the underlying transport.
    fn into_transport(self) -> Transport;
}

/// Trait for implementations that drive
/// protocol to completion.
pub(crate) trait ProtocolDriver {
    /// Error type for results.
    type Error: std::fmt::Debug
        + From<mpc_client::Error>
        + From<Box<crate::Error>>;

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

/// Run distributed key generation.
#[cfg(feature = "cggmp")]
pub async fn keygen(
    options: SessionOptions,
    party: PartyOptions,
    session_id: SessionId,
    signer: SigningKey,
) -> Result<KeyShare> {
    match &options.protocol {
        Protocol::Cggmp => Ok(crate::cggmp::keygen(
            options, party, session_id, signer,
        )
        .await?
        .into()),
    }
}

/// Sign a message.
#[cfg(feature = "cggmp")]
pub async fn sign(
    options: SessionOptions,
    participants: Option<Vec<Vec<u8>>>,
    session_id: SessionId,
    signer: SigningKey,
    selected_participants: Vec<VerifyingKey>,
    key_share: PrivateKey,
    message: &PrehashedMessage,
) -> Result<Signature> {
    let mut selected_parties = BTreeSet::new();
    selected_parties.extend(selected_participants.iter());

    match (&options.protocol, &key_share) {
        (Protocol::Cggmp, PrivateKey::Cggmp(key_share)) => {
            Ok(cggmp::sign(
                options,
                participants,
                session_id,
                signer,
                selected_participants,
                &key_share.to_key_share(&selected_parties),
                message,
            )
            .await?
            .into())
        }
    }
}

#[doc(hidden)]
/// Compute the address of an uncompressed public key (65 bytes).
pub fn address(public_key: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    // Remove the leading 0x04
    let bytes = &public_key[1..];
    let digest = Keccak256::digest(bytes);
    let final_bytes = &digest[12..];
    format!("0x{}", hex::encode(final_bytes))
}

/// Create a new client using the provided session options.
pub(crate) async fn new_client(
    options: SessionOptions,
) -> Result<(Client, EventLoop)> {
    let server_url = options.server.server_url;
    let options = ClientOptions {
        keypair: options.keypair,
        server_public_key: options.server.server_public_key,
        pattern: options.server.pattern,
    };
    let url = options.url(&server_url);
    Ok(Client::new(&url, options).await?)
}

#[cfg(feature = "cggmp")]
pub(crate) fn key_to_str(
    key: &crate::k256::ecdsa::VerifyingKey,
) -> String {
    hex::encode(&key.to_encoded_point(true).as_bytes()[1..5])
}

#[cfg(feature = "cggmp")]
pub(crate) fn public_key_to_str(public_key: &[u8]) -> String {
    hex::encode(&public_key[0..6])
}
