//! Signing for the GG20 protocol.
use wasm_bindgen::prelude::*;

use crate::{new_client_with_keypair, PrivateKey, SessionOptions};
use futures::{select, FutureExt, StreamExt};
use mpc_driver::{
    gg20::{
        self, OfflineResult, ParticipantDriver, PreSignDriver,
        Signature, SignatureDriver,
    },
    wait_for_session, Driver, SessionHandler, SessionInitiator,
    SessionParticipant,
};
use mpc_protocol::{Parameters, PartyNumber, SessionState};
use mpc_relay_client::{EventStream, NetworkTransport, Transport};

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
            Some(options.session_id),
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
    let (transport, participants) = wait_for_participants(
        &mut stream,
        transport,
        options.parameters,
        session.clone(),
        &local_key,
    )
    .await?;

    // Wait for offline stage to complete
    let (transport, offline_result) = wait_for_offline_stage(
        &mut stream,
        transport,
        options.parameters,
        session.clone(),
        local_key,
        participants,
    )
    .await?;

    // Wait for message to be signed
    let (mut transport, signature) = wait_for_signature(
        &mut stream,
        transport,
        options.parameters,
        session,
        offline_result,
        message,
    )
    .await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(session_id).await?;
    }
    transport.close().await?;

    Ok(serde_wasm_bindgen::to_value(&signature)?)
}

async fn wait_for_participants(
    stream: &mut EventStream,
    transport: Transport,
    parameters: Parameters,
    session: SessionState,
    local_key: &gg20::KeyShare,
) -> Result<(Transport, Vec<u16>), JsValue> {
    let mut part = ParticipantDriver::new(
        transport,
        parameters,
        session,
        PartyNumber::new(local_key.i).unwrap(),
    )?;

    // Get participant party numbers assigned when the local
    // keys were generated.
    part.execute().await?;

    #[allow(unused_assignments)]
    let mut participants: Option<Vec<u16>> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(list) =
                            part.handle_event(event).await? {
                            participants = Some(list);
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((part.into(), participants.take().unwrap()))
}

async fn wait_for_offline_stage(
    stream: &mut EventStream,
    transport: Transport,
    parameters: Parameters,
    session: SessionState,
    local_key: gg20::KeyShare,
    participants: Vec<u16>,
) -> Result<(Transport, OfflineResult), JsValue> {
    let mut presign = PreSignDriver::new(
        transport,
        parameters,
        session,
        local_key,
        participants,
    )?;

    presign.execute().await?;

    #[allow(unused_assignments)]
    let mut offline_stage: Option<OfflineResult> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(completed_offline_stage) =
                            presign.handle_event(event).await? {
                            offline_stage = Some(completed_offline_stage);
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((presign.into(), offline_stage.take().unwrap()))
}

async fn wait_for_signature(
    stream: &mut EventStream,
    transport: Transport,
    parameters: Parameters,
    session: SessionState,
    offline_result: OfflineResult,
    message: [u8; 32],
) -> Result<(Transport, Signature), JsValue> {
    let mut signer = SignatureDriver::new(
        transport,
        parameters,
        session,
        offline_result,
        message,
    )?;

    signer.execute().await?;

    #[allow(unused_assignments)]
    let mut signature: Option<Signature> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(sig) =
                            signer.handle_event(event).await? {
                            signature = Some(sig);
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((signer.into(), signature.take().unwrap()))
}
