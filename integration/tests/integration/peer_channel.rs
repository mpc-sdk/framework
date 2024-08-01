use crate::test_utils::{
    peer_channel, server_public_key, spawn_server,
};
use anyhow::Result;
use serial_test::serial;

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
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    peer_channel::run(&server, server_public_key).await?;

    Ok(())
}
