//! Driver for the FROST Ed25519 protocol.
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    Identifier,
};

mod key_gen;
pub use key_gen::KeyGenDriver;

use super::Error;
use mpc_client::{NetworkTransport, Transport};
use mpc_protocol::SessionId;

use crate::{
    new_client, wait_for_close, wait_for_driver, wait_for_session,
    Participant, SessionHandler, SessionInitiator, SessionOptions,
    SessionParticipant,
};

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
    )?;

    let (transport, key_share) =
        wait_for_driver(&mut stream, key_gen).await?;

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(key_share)
}
