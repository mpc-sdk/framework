use crate::test_utils::{new_client, spawn_server};
use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use mpc_relay_client::Event;
use serial_test::serial;
use tokio::sync::broadcast;

/// Creates three clients that handshake with the server
/// and then each other.
///
/// Once the handshakes are complete a session is created 
/// and the initiator broadcasts a message to all participants.
#[tokio::test]
#[serial]
async fn integration_session_broadcast() -> Result<()> {
    crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    // Create new clients
    let (mut initiator, mut event_loop_i, _) = new_client().await?;
    let (mut participant_1, mut event_loop_p_1, participant_key_1) =
        new_client().await?;
    let (mut participant_2, mut event_loop_p_2, participant_key_2) =
        new_client().await?;

    // Copy clients to move into the event loops
    let mut init_client = initiator.clone();
    let mut part_1_client = participant_1.clone();
    let mut part_2_client = participant_2.clone();

    let last_connected_peer = participant_key_2.public.clone();
    let session_participants = vec![
        participant_key_1.public.clone(),
        participant_key_2.public.clone(),
    ];

    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Setup event loops
    let shutdown_init_tx = shutdown_tx.clone();
    let ev_i = tokio::task::spawn(async move {
        let mut s = event_loop_i.run();
        while let Some(event) = s.next().await {
            let event = event?;
            tracing::trace!("initiator {:#?}", event);
            match &event {
                Event::PeerConnected { peer_key } => {
                    if peer_key == &last_connected_peer {
                        let session_response = init_client.new_session(
                            session_participants.clone()).await?;
                    }
                }
                Event::SessionReady(session) => {
                    if session.connected == session_participants {
                        println!("all participants are ready..");
                    } else {
                        panic!("expected all participants to be connected");
                    }
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut shutdown_1_rx = shutdown_tx.subscribe();
    let ev_p_1 = tokio::task::spawn(async move {
        let mut s = event_loop_p_1.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            //tracing::trace!("participant {:#?}", event);
                            match &event {

                                /*
                                Event::JsonMessage { peer_key, message } => {
                                    let message: &str = message.deserialize()?;
                                    if message == "ping" {
                                        part_1_client.send(&peer_key, "pong").await?;
                                    }
                                }
                                */
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                shutdown = shutdown_1_rx.recv().fuse() => {
                    if shutdown.is_ok() {
                        break;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut shutdown_2_rx = shutdown_tx.subscribe();
    let ev_p_2 = tokio::task::spawn(async move {
        let mut s = event_loop_p_2.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            //tracing::trace!("participant {:#?}", event);
                            match &event {
                                /*
                                Event::JsonMessage { peer_key, message } => {
                                    let message: &str = message.deserialize()?;
                                    if message == "ping" {
                                        part_2_client.send(&peer_key, "pong").await?;
                                    }
                                }
                                */
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                shutdown = shutdown_2_rx.recv().fuse() => {
                    if shutdown.is_ok() {
                        break;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Clients must handshake with the server first
    initiator.connect().await?;
    participant_1.connect().await?;
    participant_2.connect().await?;

    // Connect to the peers
    initiator.connect_peer(&participant_key_1.public).await?;
    initiator.connect_peer(&participant_key_2.public).await?;

    // Must drive the event loop futures
    let (res_i, res_p_1, res_p_2) = futures::join!(ev_i, ev_p_1, ev_p_2);

    assert!(res_i?.is_ok());
    assert!(res_p_1?.is_ok());
    assert!(res_p_2?.is_ok());

    Ok(())
}
