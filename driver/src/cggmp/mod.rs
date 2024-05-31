//! Driver for the CGGMP protocol.
use serde::{Deserialize, Serialize};
use synedrion::{
    ecdsa::{self, SigningKey, VerifyingKey},
    CombinedMessage, KeyShare as SynedrionKeyShare, PrehashedMessage,
    RecoverableSignature, SchemeParams,
};

mod aux_gen;
mod error;
mod helpers;
mod keygen;
mod sign;

pub use aux_gen::AuxGenDriver;
pub use error::Error;
pub use keygen::KeyGenDriver;

type MessageOut = (
    VerifyingKey,
    VerifyingKey,
    CombinedMessage<ecdsa::Signature>,
);

/// Key share.
#[cfg(not(debug_assertions))]
pub type KeyShare =
    SynedrionKeyShare<synedrion::ProductionParams, VerifyingKey>;

/// Key share.
#[cfg(debug_assertions)]
pub type KeyShare =
    SynedrionKeyShare<synedrion::TestParams, VerifyingKey>;

pub use sign::{
    // OfflineResult, ParticipantDriver, PreSignDriver, Signature,
    SignatureDriver,
};

/// Result type for the CGGMP protocol.
pub type Result<T> = std::result::Result<T, Error>;

/// Generated signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[deprecated]
pub struct Signature {}

use mpc_client::{NetworkTransport, Transport};

use crate::{
    new_client, wait_for_close, wait_for_driver, wait_for_session,
    wait_for_session_finish, SessionHandler, SessionInitiator,
    SessionOptions, SessionParticipant,
};

/// Run distributed key generation for the CGGMP protocol.
pub async fn keygen<P: SchemeParams + 'static>(
    options: SessionOptions,
    participants: Option<Vec<Vec<u8>>>,
    shared_randomness: &[u8],
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
) -> crate::Result<SynedrionKeyShare<P, VerifyingKey>> {
    let is_initiator = participants.is_some();

    let parameters = options.parameters;

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if let Some(participants) = participants {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let session_id = session.session_id;

    // Wait for key generation
    let keygen = KeyGenDriver::<P>::new(
        transport,
        parameters,
        session,
        shared_randomness,
        signer,
        verifiers,
    )?;

    let (mut transport, key_share) =
        wait_for_driver(&mut stream, keygen).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(session_id).await?;
        wait_for_session_finish(&mut stream, session_id).await?;
    }

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(key_share)
}

/// Sign a message using the CGGMP protocol.
pub async fn sign<P: SchemeParams + 'static>(
    options: SessionOptions,
    participants: Option<Vec<Vec<u8>>>,
    shared_randomness: &[u8],
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
    key_share: &SynedrionKeyShare<P, VerifyingKey>,
    prehashed_message: &PrehashedMessage,
) -> crate::Result<RecoverableSignature> {
    let is_initiator = participants.is_some();

    let parameters = options.parameters;

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if let Some(participants) = participants {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };
    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let session_id = session.session_id;

    /*
    // Wait for participant party numbers
    let driver = ParticipantDriver::new(
        transport,
        parameters,
        session.clone(),
        PartyNumber::new(local_key.i).unwrap(),
    )?;
    let (transport, participants) =
        wait_for_driver(&mut stream, driver).await?;
    */

    // Wait for aux gen protocol to complete
    let driver = AuxGenDriver::new(
        transport,
        parameters,
        session.clone(),
        shared_randomness,
        signer.clone(),
        verifiers.clone(),
    )?;
    let (transport, aux_info) =
        wait_for_driver(&mut stream, driver).await?;

    // Wait for message to be signed
    let driver = SignatureDriver::new(
        transport,
        // parameters,
        session,
        shared_randomness,
        signer,
        verifiers,
        key_share,
        &aux_info,
        prehashed_message,
    )?;
    let (mut transport, signature) =
        wait_for_driver(&mut stream, driver).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(session_id).await?;
        wait_for_session_finish(&mut stream, session_id).await?;
    }
    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(signature)
}
