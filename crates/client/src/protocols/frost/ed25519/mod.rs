//! Driver for the FROST Ed25519 protocol.
use polysig_driver::{
    frost::ed25519::{KeyShare, Participant, Signature},
    frost_ed25519::Identifier,
};

use crate::{
    new_client, wait_for_close, wait_for_driver, wait_for_session,
    wait_for_session_finish, Error, NetworkTransport, SessionHandler,
    SessionInitiator, SessionOptions, SessionParticipant, Transport,
};

mod key_gen;
mod sign;

pub use key_gen::KeyGenDriver;
pub use sign::SignatureDriver;

/// Run threshold DKG for the FROST protocol.
pub async fn keygen(
    options: SessionOptions,
    participant: Participant,
) -> crate::Result<KeyShare> {
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

    let mut identifiers: Vec<Identifier> =
        Vec::with_capacity(n.into());
    for index in 1..=n {
        identifiers.push(index.try_into().map_err(Error::from)?);
    }

    let key_gen =
        KeyGenDriver::new(transport, session, n, t, identifiers)?;

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
    // Identifiers must match the KeyPackage identifiers!
    identifiers: Vec<Identifier>,
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

    // Wait for message to be signed
    let driver = SignatureDriver::new(
        transport,
        session,
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
