use crate::test_utils::{
    new_client, peer_channel, server_public_key, spawn_server, SERVER,
};
use anyhow::Result;

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

    let server_public_key = server_public_key().await?;

    // Create new clients
    let (initiator, event_loop_i, initiator_key) =
        new_client::<anyhow::Error>(
            SERVER,
            server_public_key.clone(),
        )
        .await?;
    let (participant, event_loop_p, _participant_key) =
        new_client::<anyhow::Error>(
            SERVER,
            server_public_key.clone(),
        )
        .await?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let ev_i = peer_channel::initiator_client::<anyhow::Error>(
        initiator,
        event_loop_i,
        shutdown_tx,
    );
    let ev_p = peer_channel::participant_client::<anyhow::Error>(
        participant,
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
