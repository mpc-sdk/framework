//! Signing for the GG20 protocol.
use wasm_bindgen::prelude::*;

use crate::{new_client_with_keypair, PrivateKey, SessionOptions};
use mpc_client::{NetworkTransport, Transport};
use mpc_driver::{
    gg20::{ParticipantDriver, PreSignDriver, SignatureDriver},
    wait_for_driver, wait_for_session, SessionHandler,
    SessionInitiator, SessionParticipant,
};
use mpc_protocol::PartyNumber;

pub(crate) async fn sign(
    options: SessionOptions,
    PrivateKey::GG20(local_key): PrivateKey,
    message: [u8; 32],
    participants: Option<Vec<Vec<u8>>>,
) -> Result<JsValue, JsValue> {
    let is_initiator = participants.is_some();

    // Create the client
    let (client, event_loop) = new_client_with_keypair(
        &options.server.server_url,
        options.server.server_public_key.clone(),
        options.keypair.clone(),
    )
    .await?;

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
            options.session_id,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };
    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let session_id = session.session_id;

    // Wait for participant party numbers
    let driver = ParticipantDriver::new(
        transport,
        options.parameters,
        session.clone(),
        PartyNumber::new(local_key.i).unwrap(),
    )?;
    let (transport, participants) =
        wait_for_driver(&mut stream, driver).await?;

    // Wait for offline stage to complete
    let driver = PreSignDriver::new(
        transport,
        options.parameters,
        session.clone(),
        local_key,
        participants,
    )?;
    let (transport, offline_result) =
        wait_for_driver(&mut stream, driver).await?;

    // Wait for message to be signed
    let driver = SignatureDriver::new(
        transport,
        options.parameters,
        session,
        offline_result,
        message,
    )?;
    let (mut transport, signature) =
        wait_for_driver(&mut stream, driver).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(session_id).await?;
    }
    transport.close().await?;

    Ok(serde_wasm_bindgen::to_value(&signature)?)
}
