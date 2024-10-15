//! Drive multi-party computation protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
use async_trait::async_trait;
use mpc_client::{
    Client, ClientOptions, Event, EventLoop, Transport,
};
use mpc_protocol::hex;
use std::collections::BTreeSet;

#[cfg(feature = "schnorr")]
pub mod schnorr;

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
pub use types::{
    KeyShare, MeetingOptions, Participant, PartyOptions, PrivateKey,
    Protocol, ServerOptions, SessionOptions, Signature,
};

/// Result type for the driver library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "cggmp")]
pub mod cggmp;
#[cfg(feature = "cggmp")]
pub use synedrion::{self, bip32, k256};

#[cfg(feature = "cggmp")]
use synedrion::{PrehashedMessage, SessionId};

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
    participant: Participant,
    session_id: SessionId,
) -> Result<KeyShare> {
    match &options.protocol {
        Protocol::Cggmp => {
            Ok(crate::cggmp::keygen(options, participant, session_id)
                .await?
                .into())
        }
    }
}

/// Sign a message.
#[cfg(feature = "cggmp")]
pub async fn sign(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
    key_share: &PrivateKey,
    message: &PrehashedMessage,
) -> Result<Signature> {
    let mut selected_parties = BTreeSet::new();
    selected_parties.extend(participant.party().verifiers().iter());

    match (&options.protocol, key_share) {
        (Protocol::Cggmp, PrivateKey::Cggmp(key_share)) => {
            Ok(cggmp::sign(
                options,
                participant,
                session_id,
                &key_share.to_key_share(&selected_parties),
                message,
            )
            .await?
            .into())
        }
    }
}

/// Reshare key shares.
#[cfg(feature = "cggmp")]
pub async fn reshare(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
    account_verifying_key: k256::ecdsa::VerifyingKey,
    key_share: Option<&PrivateKey>,
    old_threshold: usize,
    new_threshold: usize,
) -> Result<KeyShare> {
    match (&options.protocol, key_share) {
        (Protocol::Cggmp, Some(PrivateKey::Cggmp(key_share))) => {
            Ok(cggmp::reshare(
                options,
                participant,
                session_id,
                account_verifying_key,
                Some(key_share.to_owned()),
                old_threshold,
                new_threshold,
            )
            .await?
            .into())
        }
        (Protocol::Cggmp, None) => Ok(cggmp::reshare(
            options,
            participant,
            session_id,
            account_verifying_key,
            None,
            old_threshold,
            new_threshold,
        )
        .await?
        .into()),
    }
}

/// Derive a BIP32 child key.
#[cfg(feature = "cggmp")]
pub fn derive_bip32(
    key_share: &PrivateKey,
    derivation_path: &bip32::DerivationPath,
) -> Result<PrivateKey> {
    match key_share {
        PrivateKey::Cggmp(key_share) => Ok(PrivateKey::Cggmp(
            cggmp::derive_bip32(key_share, derivation_path)?,
        )),
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
