//! Distributed key generation.
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use super::{new_client_with_keypair, KeygenOptions, Protocol, KeyShare, LocalKey};
use futures::{select, FutureExt, StreamExt};
use mpc_relay_client::{Transport, NetworkTransport, EventStream};
use mpc_driver::{SessionInitiator, gg20::KeyGenerator};
use mpc_protocol::{SessionState, SessionId};

/// Initiate distributed key generation.
#[wasm_bindgen(js_name = "keygenInit")]
pub fn keygen_init(options: JsValue) -> Result<JsValue, JsError> {
    let options: KeygenOptions =
        serde_wasm_bindgen::from_value(options)?;
    match &options.protocol {
        Protocol::GG20 => {
            Ok(future_to_promise(gg20_keygen_init(options)).into())
        }
        _ => todo!("drive CGGMP protocol"),
    }
}

async fn gg20_keygen_init(
    options: KeygenOptions,
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
    let (transport, session) = wait_for_session(
        &mut stream,
        transport,
        options.participants.clone(),
        Some(options.session_id),
    ).await?;
    
    // Prepare the key generator
    let mut keygen = KeyGenerator::new(
        transport,
        options.parameters.clone(),
        session,
    )?;

    let mut key_share: Option<KeyShare> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(local_key_share) =
                            keygen.handle_event(event).await? {
                            key_share = Some(KeyShare {
                                local_key: LocalKey::GG20(local_key_share),
                            });
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    let key_share = key_share.take().unwrap();
    Ok(serde_wasm_bindgen::to_value(&key_share)?)
}

async fn wait_for_session(
    stream: &mut EventStream,
    transport: Transport,
    participants: Vec<Vec<u8>>,
    session_id: Option<SessionId>,
) -> Result<(Transport, SessionState), JsValue> {
    let mut client_session = SessionInitiator::new(
        transport,
        participants.clone(),
        session_id,
    );
    let mut session: Option<SessionState> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(active_session) =
                            client_session.create(event).await? {
                            session = Some(active_session);
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((client_session.into(), session.take().unwrap()))
}
