use anyhow::Result;
use serial_test::serial;

use crate::test_utils::{
    server_public_key, session_handshake, spawn_server, SERVER,
};

/// Uses the session helpers from the driver library to determine
/// when both participants in a session are active.
#[tokio::test]
#[serial]
async fn integration_session_handshake() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    let expected_participants = 2;
    let connected_participants =
        session_handshake::run(SERVER, server_public_key).await?;
    assert_eq!(expected_participants, connected_participants);

    Ok(())
}
