use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;

use mpc_relay_client::{Client, Event};
use mpc_relay_protocol::SessionState;

use super::new_client;

type SessionResult = Arc<Mutex<Vec<u8>>>;

#[derive(Default)]
pub struct ClientState {
    session: Option<SessionState>,
    received: u8,
}

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<SessionResult> {
    let mut completed: Vec<u8> = Vec::new();
    let session_result = Arc::new(Mutex::new(vec![]));

    let state_1 = Arc::new(Mutex::new(Default::default()));
    let state_2 = Arc::new(Mutex::new(Default::default()));
    let state_3 = Arc::new(Mutex::new(Default::default()));

    // Create new clients
    let (mut client_i, event_loop_i, _) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (mut client_p_1, event_loop_p_1, participant_key_1) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (mut client_p_2, event_loop_p_2, participant_key_2) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let session_participants = vec![
        participant_key_1.public.clone(),
        participant_key_2.public.clone(),
    ];

    // Each client handshakes with the server
    client_i.connect().await?;
    client_p_1.connect().await?;
    client_p_2.connect().await?;

    let mut s_i = event_loop_i.run();
    let mut s_p_1 = event_loop_p_1.run();
    let mut s_p_2 = event_loop_p_2.run();

    loop {
        completed.sort();

        if completed == vec![1u8, 2u8, 3u8] {
            break;
        }

        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if !completed.contains(&1u8) {
                            let done = initiator(
                                1u8,
                                &mut client_i,
                                event,
                                session_participants.clone(),
                                Arc::clone(&state_1),
                                Arc::clone(&session_result),
                            ).await?;

                            if done {
                                completed.push(1u8);
                            }
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if !completed.contains(&2u8) {
                            let done = participant(
                                2u8,
                                &mut client_p_1,
                                event,
                                Arc::clone(&state_2),
                                Arc::clone(&session_result),
                            ).await?;

                            if done {
                                completed.push(2u8);
                            }
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if !completed.contains(&3u8) {
                            let done = participant(
                                3u8,
                                &mut client_p_2,
                                event,
                                Arc::clone(&state_3),
                                Arc::clone(&session_result),
                            ).await?;

                            if done {
                                completed.push(3u8);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(session_result)
}

/// Event handler for the session initiator.
async fn initiator(
    number: u8,
    client: &mut Client,
    event: Event,
    session_participants: Vec<Vec<u8>>,
    session_state: Arc<Mutex<ClientState>>,
    session_result: SessionResult,
) -> Result<bool> {
    match event {
        Event::ServerConnected { .. } => {
            tracing::info!("initiator connected to server");
            // Initiate a session context for broadcasting
            client.new_session(session_participants).await?;
        }
        Event::SessionCreated(session) => {
            tracing::info!(
                id = ?session.session_id.to_string(),
                "session created");
        }
        Event::SessionReady(session) => {
            let mut state = session_state.lock().await;
            state.session = Some(session.clone());

            tracing::info!(
                id = ?session.session_id.to_string(),
                "initiator session ready");

            for key in session.connections(client.public_key()) {
                client.connect_peer(key).await?;
            }
        }
        Event::PeerConnected { peer_key } => {
            let state = session_state.lock().await;
            let session = state.session.as_ref().unwrap();
            let connections =
                session.connections(client.public_key());
            if connections.contains(&peer_key) {
                client
                    .register_session_connection(
                        &session.session_id,
                        peer_key.as_slice(),
                    )
                    .await?;
            }
        }
        Event::SessionActive(session) => {
            let message = number;
            let session_id = session.session_id.clone();
            let mut recipients = session.all_participants;
            let own_key = client.public_key();
            recipients.retain(|k| k != own_key);
            client
                .broadcast_json(
                    &session_id,
                    recipients.as_slice(),
                    &message,
                )
                .await?;
        }
        Event::JsonMessage {
            message,
            session_id,
            ..
        } => {
            let message: u8 = message.deserialize()?;
            let mut result = session_result.lock().await;
            result.push(message);

            let mut state = session_state.lock().await;
            state.received += 1;

            assert_eq!(
                &state.session.as_ref().unwrap().session_id,
                session_id.as_ref().unwrap()
            );

            if state.received == 2 {
                let session_id =
                    state.session.as_ref().unwrap().session_id;
                client.close_session(session_id).await?;
            }
        }
        Event::SessionFinished(session_id) => {
            let state = session_state.lock().await;
            let current_session_id =
                state.session.as_ref().unwrap().session_id;
            assert_eq!(current_session_id, session_id);
            return Ok(true);
        }
        _ => {}
    }
    Ok(false)
}

/// Event handler for a participant.
async fn participant(
    number: u8,
    client: &mut Client,
    event: Event,
    session_state: Arc<Mutex<ClientState>>,
    session_result: SessionResult,
) -> Result<bool> {
    match event {
        Event::SessionReady(session) => {
            tracing::info!(
                id = ?session.session_id.to_string(),
                "participant session ready");

            let mut state = session_state.lock().await;
            state.session = Some(session.clone());

            for key in session.connections(client.public_key()) {
                client.connect_peer(key).await?;
            }
        }
        Event::PeerConnected { peer_key } => {
            let state = session_state.lock().await;
            let session = state.session.as_ref().unwrap();
            let connections =
                session.connections(client.public_key());
            if connections.contains(&peer_key) {
                client
                    .register_session_connection(
                        &session.session_id,
                        peer_key.as_slice(),
                    )
                    .await?;
            }
        }
        Event::SessionActive(session) => {
            let message = number;
            let session_id = session.session_id.clone();
            let mut recipients = session.all_participants;
            let own_key = client.public_key();
            recipients.retain(|k| k != own_key);
            client
                .broadcast_json(
                    &session_id,
                    recipients.as_slice(),
                    &message,
                )
                .await?;
        }
        Event::JsonMessage {
            message,
            session_id,
            ..
        } => {
            let message: u8 = message.deserialize()?;
            let mut result = session_result.lock().await;
            result.push(message);

            let mut state = session_state.lock().await;
            state.received += 1;

            assert_eq!(
                &state.session.as_ref().unwrap().session_id,
                session_id.as_ref().unwrap()
            );

            if state.received == 2 {
                return Ok(true);
            }
        }
        _ => {}
    }
    Ok(false)
}
