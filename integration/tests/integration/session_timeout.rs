use crate::test_utils::{
    server_public_key, session_timeout, spawn_server,
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
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    session_timeout::run(&server, server_public_key).await?;

    Ok(())
}
