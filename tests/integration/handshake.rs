use crate::test_utils::{init_tracing, new_client, spawn_server};
use anyhow::Result;
use futures::StreamExt;
use mpc_relay_client::Event;
use serial_test::serial;
use tokio::sync::oneshot;

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    // Create new clients
    let (mut initiator, mut event_loop_i, initiator_key) =
        new_client().await?;
    let (mut participant, mut event_loop_p, participant_key) =
        new_client().await?;

    // Copy clients to move into the event loops
    let mut init_client = initiator.clone();
    let mut part_client = participant.clone();

    let init_public = initiator_key.public.clone();
    let part_public = participant_key.public.clone();

    // Setup event loops
    let ev_i = tokio::task::spawn(async move {
        let mut s = event_loop_i.run();
        while let Some(event) = s.next().await {
            let event = event?;
            //tracing::info!("initiator {:#?}", event);
            match &event {
                // Once the peer connection is established we can
                // start sending messages over the encrypted channel
                Event::PeerConnected { .. } => {
                    init_client.send(&part_public, "ping").await?;
                }
                Event::JsonMessage { peer_key, message } => {
                    let message: String = message.deserialize()?;
                    if &message == "pong" {
                        println!("GOT PONG");
                        break;
                    }
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let ev_p = tokio::task::spawn(async move {
        let mut s = event_loop_p.run();
        while let Some(event) = s.next().await {
            let event = event?;
            //tracing::info!("participant {:#?}", event);

            match &event {
                // Once the peer connection is established we can
                // start sending messages over the encrypted channel
                Event::JsonMessage { peer_key, message } => {
                    let message: String = message.deserialize()?;
                    if &message == "ping" {
                        part_client.send(&peer_key, "pong").await?;
                    }
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Clients must handshake with the server first
    initiator.handshake().await?;
    participant.handshake().await?;

    // Now we can connect to a peer
    initiator.connect_peer(&participant_key.public).await?;

    // Must drive the event loop futures
    let (res1, res2) = futures::join!(ev_i, ev_p);

    println!("init {:#?}", res1);
    println!("part {:#?}", res2);

    Ok(())
}
