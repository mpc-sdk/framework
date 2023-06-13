use anyhow::Result;
use futures::{select, FutureExt, StreamExt, Future};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};
use tokio_stream::wrappers::IntervalStream;

use mpc_relay_client::{Client, Event, EventLoop};
use mpc_relay_protocol::{SessionId, SessionState};

type SessionResult = Arc<Mutex<Vec<u8>>>;

#[derive(Default)]
pub struct ClientState {
    session: Option<SessionState>,
    received: u8,
}

pub async fn client_1(
    event_loop: EventLoop,
    mut client: Client,
    session_result: SessionResult,
    session_participants: Vec<Vec<u8>>,
) -> Result<impl Future<Output = Result<()>>> {
    let session_state = Arc::new(Mutex::new(Default::default()));

    // Channel used to shutdown polling for session ready
    let (mut ready_tx, ready_rx) = mpsc::channel::<()>(32);
    let ready_rx = Arc::new(Mutex::new(ready_rx));

    // Channel used to shutdown polling for session active
    let (mut active_tx, active_rx) = mpsc::channel::<()>(32);
    let active_rx = Arc::new(Mutex::new(active_rx));

    // Server handshake
    client.connect().await?;
    
    Ok(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            let done = initiator(
                                1u8,
                                &mut client,
                                event,
                                session_participants.clone(),
                                &mut ready_tx,
                                Arc::clone(&ready_rx),
                                &mut active_tx,
                                Arc::clone(&active_rx),
                                Arc::clone(&session_state),
                                Arc::clone(&session_result),
                            ).await?;

                            if done {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    })
}

pub async fn client_2(
    event_loop: EventLoop,
    mut client: Client,
    session_result: SessionResult,
) -> Result<impl Future<Output = Result<()>>> {
    let session_state = Arc::new(Mutex::new(Default::default()));

    // Server handshake
    client.connect().await?;

    Ok(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            let done = participant(
                                2u8,
                                &mut client,
                                event,
                                Arc::clone(&session_state),
                                Arc::clone(&session_result),
                            ).await?;

                            if done {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

pub async fn client_3(
    event_loop: EventLoop,
    mut client: Client,
    session_result: SessionResult,
) -> Result<impl Future<Output = Result<()>>> {
    let session_state = Arc::new(Mutex::new(Default::default()));

    // Server handshake
    client.connect().await?;

    Ok(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            let done = participant(
                                3u8,
                                &mut client,
                                event,
                                Arc::clone(&session_state),
                                Arc::clone(&session_result),
                            ).await?;

                            if done {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

/// Poll the server to trigger a notification when
/// all the session participants have established
/// a connection to the server.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn poll_session_ready(
    mut client: Client,
    session_id: SessionId,
    ready_rx: Arc<Mutex<mpsc::Receiver<()>>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let interval_secs = 1;
        let interval =
            tokio::time::interval(Duration::from_secs(interval_secs));
        let mut stream = IntervalStream::new(interval);
        let mut stop_polling = ready_rx.lock().await;
        loop {
            select! {
                tick = stream.next().fuse() => {
                    if tick.is_some() {
                        client.session_ready_notify(&session_id).await?;
                    }
                }
                _ = stop_polling.recv().fuse() => {
                    break;
                }
            }
        }
        Ok(())
    })
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn poll_session_ready(
    mut client: Client,
    session_id: SessionId,
    ready_rx: Arc<Mutex<mpsc::Receiver<()>>>,
) {
    wasm_bindgen_futures::spawn_local(async move {
        let interval_secs = 1;
        let mut stop_polling = ready_rx.lock().await;
        loop {
            log::info!("polling for ready..");
            std::thread::sleep(Duration::from_secs(interval_secs));
            client.session_ready_notify(&session_id).await.unwrap();
        }
    })
}

/// Poll the server to trigger a notification when
/// all the session participants have established
/// connections to each other.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn poll_session_active(
    mut client: Client,
    session_id: SessionId,
    active_rx: Arc<Mutex<mpsc::Receiver<()>>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let interval_secs = 1;
        let interval =
            tokio::time::interval(Duration::from_secs(interval_secs));
        let mut stream = IntervalStream::new(interval);
        let mut stop_polling = active_rx.lock().await;
        loop {
            select! {
                tick = stream.next().fuse() => {
                    if tick.is_some() {
                        client.session_active_notify(&session_id).await?;
                    }
                }
                _ = stop_polling.recv().fuse() => {
                    break;
                }
            }
        }
        Ok(())
    })
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn poll_session_active(
    mut client: Client,
    session_id: SessionId,
    active_rx: Arc<Mutex<mpsc::Receiver<()>>>,
) {
    wasm_bindgen_futures::spawn_local(async move {
        let interval_secs = 1;
        let mut stop_polling = active_rx.lock().await;
        loop {
            log::info!("polling for active..");
            std::thread::sleep(Duration::from_secs(interval_secs));
            client.session_active_notify(&session_id).await.unwrap();
        }
    })
}

/// Event handler for the session initiator.
async fn initiator(
    number: u8,
    client: &mut Client,
    event: Event,
    session_participants: Vec<Vec<u8>>,
    ready_tx: &mut mpsc::Sender<()>,
    ready_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    active_tx: &mut mpsc::Sender<()>,
    active_rx: Arc<Mutex<mpsc::Receiver<()>>>,
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
            // Spawn a task to poll the session
            // so that we receive a notification
            // whan all participants have connected
            // to the server
            poll_session_ready(
                client.clone(),
                session.session_id,
                ready_rx,
            );
        }
        Event::SessionReady(session) => {
            // Stop polling
            ready_tx.send(()).await?;

            let mut state = session_state.lock().await;
            state.session = Some(session.clone());

            tracing::info!(
                id = ?session.session_id.to_string(),
                "initiator session ready");

            // Start polling for the session active notification
            poll_session_active(
                client.clone(),
                session.session_id,
                active_rx,
            );

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
            // Stop polling
            active_tx.send(()).await?;

            let message = number;
            let session_id = session.session_id.clone();
            let mut recipients = session.all_participants;
            let own_key = client.public_key();
            recipients.retain(|k| k != own_key);
            client
                .broadcast(
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
                .broadcast(
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
