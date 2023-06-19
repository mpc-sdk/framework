//! Distributed key generation for the GG20 protocol.
use wasm_bindgen::prelude::*;

use crate::{new_client_with_keypair, KeyShare, SessionOptions};
use futures::{select, FutureExt, StreamExt};
use mpc_driver::{
    gg20::KeyGenerator, wait_for_session, SessionInitiator,
    SessionParticipant, SessionHandler, Driver,
};
use mpc_relay_client::{EventStream, NetworkTransport, Transport};

pub(crate) async fn keygen(
    options: SessionOptions,
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
            Some(options.session_id),
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(transport))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let session_id = session.session_id;

    // Wait for key generation
    let keygen = KeyGenerator::new(
        transport,
        options.parameters.clone(),
        session,
    )?;
    let (mut transport, key_share) =
        wait_for_key_share(&mut stream, keygen).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(session_id).await?;
    }
    transport.close().await?;

    Ok(serde_wasm_bindgen::to_value(&key_share)?)
}

/*
pub(crate) async fn keygen_join(
    options: SessionOptions,
) -> Result<JsValue, JsValue> {
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
    let client_session = SessionParticipant::new(transport);
    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    // Wait for key generation
    let keygen = KeyGenerator::new(
        transport,
        options.parameters.clone(),
        session,
    )?;
    let (transport, key_share) =
        wait_for_key_share(&mut stream, keygen).await?;

    // Close the socket
    transport.close().await?;

    Ok(serde_wasm_bindgen::to_value(&key_share)?)
}
*/

async fn wait_for_key_share(
    stream: &mut EventStream,
    mut keygen: KeyGenerator,
) -> Result<(Transport, KeyShare), JsValue> {
    #[allow(unused_assignments)]
    let mut key_share: Option<KeyShare> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(local_key_share) =
                            keygen.handle_event(event).await? {
                            key_share = Some(local_key_share.into());
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((keygen.into(), key_share.take().unwrap()))
}
