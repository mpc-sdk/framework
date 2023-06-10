use anyhow::Result;
use futures::{select, Future, FutureExt, StreamExt};
use serial_test::serial;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    task::JoinHandle,
};
use tokio_stream::wrappers::IntervalStream;

use mpc_relay_client::{Error, Event, EventLoop, NativeClient};
use mpc_relay_protocol::{SessionId, SessionState};

use crate::test_utils::{new_client, spawn_server};

/// Creates three clients that handshake with the server
/// and then each other.
///
/// Once the handshakes are complete a session is created
/// and the initiator broadcasts a message to all participants.
#[tokio::test]
#[serial]
async fn integration_session_broadcast() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    // Create new clients
    let (initiator, event_loop_i, _) = new_client().await?;
    let (participant_1, event_loop_p_1, participant_key_1) =
        new_client().await?;
    let (participant_2, event_loop_p_2, participant_key_2) =
        new_client().await?;

    let session_participants = vec![
        participant_key_1.public.clone(),
        participant_key_2.public.clone(),
    ];

    /*
    let (shutdown_tx, _) = broadcast::channel::<()>(16);

    // Setup event loops
    let shutdown_init_tx = shutdown_tx.clone();
    */

    let ev_i =
        event_loop_1(event_loop_i, initiator, session_participants)
            .await?;
    let ev_p_1 = event_loop_2(event_loop_p_1, participant_1).await?;
    let ev_p_2 = event_loop_3(event_loop_p_2, participant_2).await?;

    // Must drive the event loop futures
    let (res_i, res_p_1, res_p_2) =
        futures::join!(ev_i, ev_p_1, ev_p_2);

    println!("{:#?}", res_i);

    assert!(res_i?.is_ok());
    assert!(res_p_1?.is_ok());
    assert!(res_p_2?.is_ok());

    Ok(())
}

/// Poll the server to trigger a notification when
/// all the session participants have established
/// a connection to the server.
fn poll_session_ready(
    mut client: NativeClient,
    session_id: SessionId,
    ready_rx: Arc<Mutex<mpsc::Receiver<()>>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let interval_secs = 2;
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

/// Poll the server to trigger a notification when
/// all the session participants have established
/// connections to each other.
fn poll_session_active(
    mut client: NativeClient,
    session_id: SessionId,
    active_rx: Arc<Mutex<mpsc::Receiver<()>>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let interval_secs = 2;
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

#[derive(Default)]
struct ClientState {
    session: Option<SessionState>,
    registrations: Vec<Vec<u8>>,
}

async fn event_loop_1(
    mut event_loop: EventLoop,
    mut client: NativeClient,
    session_participants: Vec<Vec<u8>>,
) -> Result<JoinHandle<Result<()>>> {
    let session_state = Arc::new(Mutex::new(Default::default()));

    // Channel used to shutdown polling for session ready
    let (mut ready_tx, ready_rx) = mpsc::channel::<()>(32);
    let ready_rx = Arc::new(Mutex::new(ready_rx));

    // Channel used to shutdown polling for session active
    let (mut active_tx, active_rx) = mpsc::channel::<()>(32);
    let active_rx = Arc::new(Mutex::new(active_rx));

    async fn handler(
        client: &mut NativeClient,
        event: Event,
        session_participants: Vec<Vec<u8>>,
        ready_tx: &mut mpsc::Sender<()>,
        ready_rx: Arc<Mutex<mpsc::Receiver<()>>>,
        active_tx: &mut mpsc::Sender<()>,
        active_rx: Arc<Mutex<mpsc::Receiver<()>>>,
        session_state: Arc<Mutex<ClientState>>,
    ) -> Result<()> {
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

                println!("init connecting to peers");
                for key in &session.all_participants {
                    if key != client.public_key() {
                        let connected = client.try_connect_peer(key).await?;
                        if connected {
                            println!("init adding registration...");
                            state.registrations.push(key.to_vec());
                        }
                    }
                }
            }
            Event::PeerConnected { peer_key } => {
                println!("INIT GOT PEER CONNECTED EVENT");
                let state = session_state.lock().await;
                let session = state.session.as_ref().unwrap();
                if state.registrations.contains(&peer_key) {
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
                println!("INIT session active");
                let message = "1";
                let session_id = session.session_id.clone();
                let mut recipients = session.all_participants;
                let own_key = client.public_key();
                recipients.retain(|k| k != own_key);
                println!("recipients {}", recipients.len());

                /*
                client.broadcast(
                    &session_id, recipients.as_slice(), message).await?;
                */

            }
            _ => {}
        }
        Ok(())
    }

    // Server handshake
    client.connect().await?;

    Ok(tokio::task::spawn(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            handler(
                                &mut client,
                                event,
                                session_participants.clone(),
                                &mut ready_tx,
                                Arc::clone(&ready_rx),
                                &mut active_tx,
                                Arc::clone(&active_rx),
                                Arc::clone(&session_state),
                            ).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }))
}

async fn event_loop_2(
    mut event_loop: EventLoop,
    mut client: NativeClient,
) -> Result<JoinHandle<Result<()>>> {
    let session_state = Arc::new(Mutex::new(Default::default()));

    async fn handler(
        client: &mut NativeClient,
        event: Event,
        session_state: Arc<Mutex<ClientState>>,
    ) -> Result<()> {
        match event {
            Event::SessionReady(session) => {
                tracing::info!(
                    id = ?session.session_id.to_string(),
                    "participant(1) session ready");

                let mut state = session_state.lock().await;
                state.session = Some(session.clone());

                for key in &session.all_participants {
                    if key != client.public_key() {
                        let connected = client.try_connect_peer(key).await?;
                        if connected {
                            println!("part(1) adding registration...");
                            state.registrations.push(key.to_vec());
                        }
                    }
                }
            }
            Event::PeerConnected { peer_key } => {
                let state = session_state.lock().await;
                let session = state.session.as_ref().unwrap();
                if state.registrations.contains(&peer_key) {
                    client
                        .register_session_connection(
                            &session.session_id,
                            peer_key.as_slice(),
                        )
                        .await?;
                }
            }
            Event::SessionActive(session) => {
                println!("PART1 session active");

                let message = "2";
                let session_id = session.session_id.clone();
                let mut recipients = session.all_participants;
                let own_key = client.public_key();
                recipients.retain(|k| k != own_key);
                println!("recipients {}", recipients.len());
                /*
                client.broadcast(
                    &session_id, recipients.as_slice(), message).await?;
                */
            }

            _ => {}
        }
        Ok(())
    }

    // Server handshake
    client.connect().await?;

    Ok(tokio::task::spawn(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                /*
                _ = server_conn_rx.recv().fuse() => {
                    // Initiate a session context for broadcasting
                    init_client
                        .new_session(session_participants.clone())
                        .await?;
                }
                */
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            handler(&mut client, event, Arc::clone(&session_state)).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }))
}

async fn event_loop_3(
    mut event_loop: EventLoop,
    mut client: NativeClient,
) -> Result<JoinHandle<Result<()>>> {
    let session_state = Arc::new(Mutex::new(Default::default()));

    async fn handler(
        client: &mut NativeClient,
        event: Event,
        session_state: Arc<Mutex<ClientState>>,
    ) -> Result<()> {
        match event {
            Event::SessionReady(session) => {
                tracing::info!(
                    id = ?session.session_id.to_string(),
                    "participant(2) session ready");

                let mut state = session_state.lock().await;
                state.session = Some(session.clone());

                for key in &session.all_participants {
                    if key != client.public_key() {
                        let connected = client.try_connect_peer(key).await?;
                        if connected {
                            println!("part(2) adding registration...");
                            state.registrations.push(key.to_vec());
                        }
                    }
                }
            }
            Event::PeerConnected { peer_key } => {
                let state = session_state.lock().await;
                let session = state.session.as_ref().unwrap();
                if state.registrations.contains(&peer_key) {
                    client
                        .register_session_connection(
                            &session.session_id,
                            peer_key.as_slice(),
                        )
                        .await?;
                }
            }
            Event::SessionActive(session) => {
                println!("PART2 session active");

                let message = "3";
                let session_id = session.session_id.clone();
                let mut recipients = session.all_participants;
                let own_key = client.public_key();
                recipients.retain(|k| k != own_key);
                println!("recipients {}", recipients.len());
                /*
                client.broadcast(
                    &session_id, recipients.as_slice(), message).await?;
                */
            }
            _ => {}
        }
        Ok(())
    }

    // Server handshake
    client.connect().await?;

    Ok(tokio::task::spawn(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                /*
                _ = server_conn_rx.recv().fuse() => {
                    // Initiate a session context for broadcasting
                    init_client
                        .new_session(session_participants.clone())
                        .await?;
                }
                */
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            handler(&mut client, event, Arc::clone(&session_state)).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }))
}
