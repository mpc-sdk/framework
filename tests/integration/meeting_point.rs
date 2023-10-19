use anyhow::Result;
use serial_test::serial;

use crate::test_utils::{
    meeting_point, server_public_key, spawn_server, SERVER,
};

/// Mimics a meeting point flow for two participants.
#[tokio::test]
#[serial]
async fn integration_meeting_point() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    let expected_participants = 2;
    let connected_participants =
        meeting_point::run(SERVER, server_public_key).await?;
    assert_eq!(expected_participants, connected_participants);

    Ok(())
}
