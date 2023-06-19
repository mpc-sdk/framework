use crate::test_utils::{
    server_public_key, socket_close, spawn_server, SERVER,
};
use anyhow::Result;
use serial_test::serial;

/// Creates a client that handshakes with the server and
/// then explicitly closes the connection.
#[tokio::test]
#[serial]
async fn integration_socket_close() -> Result<()> {
    //crate::test_utils::init_tracing();
    //

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    socket_close::run(SERVER, server_public_key).await?;

    Ok(())
}
