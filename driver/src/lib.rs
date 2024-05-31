//! Drive multi-party computation protocols to completion.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
use async_trait::async_trait;
use mpc_client::{Client, ClientOptions, Event, EventLoop};
use mpc_protocol::hex;

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
pub use synedrion;
#[cfg(feature = "cggmp")]
pub use synedrion::k256;

#[cfg(feature = "cggmp")]
use synedrion::k256::ecdsa::{SigningKey, VerifyingKey};

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

    /// Whether the current round can be finalized.
    fn can_finalize(&self) -> std::result::Result<bool, Self::Error>;

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
    participants: Option<Vec<Vec<u8>>>,
    shared_randomness: &[u8],
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
) -> Result<KeyShare> {
    match &options.protocol {
        Protocol::Cggmp => Ok(crate::cggmp::keygen(
            options,
            participants,
            shared_randomness,
            signer,
            verifiers,
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
    signing_key: PrivateKey,
    message: [u8; 32],
) -> Result<Signature> {
    todo!();

    /*
    match &options.protocol {
        Protocol::GG20 => {
            assert!(matches!(signing_key, PrivateKey::GG20(_)));
            Ok(gg20::sign(
                options,
                participants,
                signing_key,
                message,
            )
            .await?
            .into())
        }
        _ => todo!("drive CGGMP protocol"),
    }
    */
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
