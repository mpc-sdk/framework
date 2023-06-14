use crate::test_utils::{
    session_timeout, server_public_key, spawn_server, SERVER,
};
use anyhow::Result;
use serial_test::serial;

/// Creates two clients that handshake with the server.
///
/// The first client creates a session but the second 
/// client never joins the session so we get a timeout event.
#[tokio::test]
#[serial]
async fn integration_session_timeout() -> Result<()> {
    //crate::test_utils::init_tracing();
    //

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    session_timeout::run(SERVER, server_public_key).await?;

    Ok(())
}
