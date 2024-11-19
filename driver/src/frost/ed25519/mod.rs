//! Driver for the FROST Ed25519 protocol.
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier, Signature,
};

mod key_gen;
mod sign;

pub use ed25519_dalek;
pub use key_gen::KeyGenDriver;
pub use sign::SignatureDriver;

use super::Error;
use mpc_client::{NetworkTransport, Transport};
use mpc_protocol::SessionId;

use crate::{
    new_client, wait_for_close, wait_for_driver, wait_for_session,
    wait_for_session_finish, SessionHandler, SessionInitiator,
    SessionOptions, SessionParticipant,
};

/// Participant in the protocol.
pub type Participant = crate::Participant<
    ed25519_dalek::SigningKey,
    ed25519_dalek::VerifyingKey,
>;

/// Options for each party.
pub type PartyOptions =
    crate::PartyOptions<ed25519_dalek::VerifyingKey>;

/// Key share for this protocol.
pub type KeyShare = (KeyPackage, PublicKeyPackage);

const ROUND_1: u8 = 1;
const ROUND_2: u8 = 2;
const ROUND_3: u8 = 3;

/// Run threshold DKG for the FROST protocol.
pub async fn keygen(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
) -> crate::Result<(KeyPackage, PublicKeyPackage)> {
    let n = options.parameters.parties;
    let t = options.parameters.threshold;

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if participant.party().is_initiator() {
        let mut other_participants =
            participant.party().participants().to_vec();
        other_participants
            .retain(|p| p != participant.party().public_key());
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            other_participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let verifiers = participant
        .party()
        .verifiers()
        .iter()
        .cloned()
        .collect::<Vec<_>>();

    let mut identifiers: Vec<Identifier> =
        Vec::with_capacity(n.into());
    for index in 1..=n {
        identifiers.push(index.try_into().map_err(Error::from)?);
    }

    let key_gen = KeyGenDriver::new(
        transport,
        session,
        session_id,
        n,
        t,
        identifiers,
        participant.signing_key().to_owned(),
        verifiers,
    )?;

    let (transport, key_share) =
        wait_for_driver(&mut stream, key_gen).await?;

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(key_share)
}

/// Sign a message using the FROST protocol.
pub async fn sign(
    options: SessionOptions,
    participant: Participant,
    session_id: SessionId,
    key_share: KeyShare,
    message: Vec<u8>,
) -> crate::Result<Signature> {
    let min_signers = options.parameters.threshold as u16;

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if participant.party().is_initiator() {
        let mut other_participants =
            participant.party().participants().to_vec();
        other_participants
            .retain(|p| p != participant.party().public_key());
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            other_participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    let mut identifiers: Vec<Identifier> =
        Vec::with_capacity(min_signers.into());
    for index in 1..=min_signers {
        identifiers.push(index.try_into().map_err(Error::from)?);
    }

    // Wait for message to be signed
    let driver = SignatureDriver::new(
        transport,
        session,
        session_id,
        participant.signing_key().clone(),
        participant.party().verifiers().to_vec(),
        identifiers,
        min_signers,
        key_share,
        message,
    )?;

    let (mut transport, signature) =
        wait_for_driver(&mut stream, driver).await?;

    // Close the session and socket
    if participant.party().is_initiator() {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }
    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(signature)
}
