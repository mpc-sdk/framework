use crate::test_utils::{new_client, spawn_server};
use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use mpc_relay_client::Event;
use serial_test::serial;
use tokio::sync::mpsc;

/// Creates two clients that handshake with the server
/// and then each other. Once the peer handshakes are
/// complete they send "ping" and "pong" messages over
/// the noise transport channel.
#[tokio::test]
#[serial]
async fn integration_peer_channel() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    // Create new clients
    let (mut initiator, mut event_loop_i, initiator_key) =
        new_client().await?;
    let (mut participant, mut event_loop_p, _participant_key) =
        new_client().await?;

    // Copy clients to move into the event loops
    let mut init_client = initiator.clone();
    let mut part_client = participant.clone();

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Setup event loops
    let ev_i = tokio::task::spawn(async move {
        initiator.connect().await?;

        let mut s = event_loop_i.run();
        while let Some(event) = s.next().await {
            let event = event?;
            tracing::trace!("initiator {:#?}", event);
            match &event {
                // Once the peer connection is established we can
                // start sending messages over the encrypted channel
                Event::PeerConnected { peer_key } => {
                    // Send the ping
                    init_client.send(&peer_key, "ping").await?;
                }
                Event::JsonMessage { message, .. } => {
                    let message: &str = message.deserialize()?;
                    if message == "pong" {
                        // Got a pong so break out of the event loop
                        shutdown_tx.send(()).await?;
                        break;
                    }
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let ev_p = tokio::task::spawn(async move {
        participant.connect().await?;

        let mut s = event_loop_p.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            tracing::trace!("participant {:#?}", event);
                            match &event {
                                Event::ServerConnected { .. } => {
                                    // Now we can connect to a peer
                                    part_client.connect_peer(&initiator_key.public).await?;
                                }
                                // Once the peer connection is established
                                // we can start sending messages over
                                // the encrypted channel
                                Event::JsonMessage { peer_key, message } => {
                                    let message: &str = message.deserialize()?;
                                    if message == "ping" {
                                        part_client.send(&peer_key, "pong").await?;
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                shutdown = shutdown_rx.recv().fuse() => {
                    if shutdown.is_some() {
                        break;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Must drive the event loop futures
    let (res_i, res_p) = futures::join!(ev_i, ev_p);

    assert!(res_i?.is_ok());
    assert!(res_p?.is_ok());

    Ok(())
}
