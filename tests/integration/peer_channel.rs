use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use mpc_relay_client::Event;
use serial_test::serial;
use tokio::sync::mpsc;
use crate::test_utils::{new_client, spawn_server, peer_channel};

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
    let (mut initiator, event_loop_i, initiator_key) =
        new_client().await?;
    let (mut participant, event_loop_p, _participant_key) =
        new_client().await?;

    // Copy clients to move into the event loops
    let mut init_client = initiator.clone();
    let mut part_client = participant.clone();

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let ev_i = peer_channel::initiator_client::<anyhow::Error>(
        init_client,
        event_loop_i,
        shutdown_tx,
    );
    let ev_p = peer_channel::participant_client::<anyhow::Error>(
        part_client,
        event_loop_p,
        &initiator_key.public,
        shutdown_rx,
    );
    
    // Must drive the event loop futures
    let (res_i, res_p) = futures::join!(ev_i, ev_p);

    assert!(res_i.is_ok());
    assert!(res_p.is_ok());

    Ok(())
}
