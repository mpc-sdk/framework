use anyhow::Result;
use serial_test::serial;

use crate::test_utils::{
    server_public_key, session_broadcast, spawn_server, SERVER,
};

/// Creates three clients that handshake with the server
/// and then each other.
///
/// Once the handshakes are complete a session is created
/// and each node broadcasts a message to all the other
/// participants in the session.
#[tokio::test]
#[serial]
async fn integration_session_broadcast() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    let expected_result = vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8];
    let session_result =
        session_broadcast::run(SERVER, server_public_key).await?;
    let mut result = session_result.lock().await;
    result.sort();
    assert_eq!(expected_result, result.clone());

    Ok(())
}
