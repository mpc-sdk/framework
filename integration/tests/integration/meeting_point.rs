use anyhow::Result;

use crate::test_utils::{
    meeting_point, server_public_key, spawn_server,
};

/// Mimics a meeting point flow for two participants.
#[tokio::test]
async fn integration_meeting_point() -> Result<()> {
    //crate::test_utils::init_tracing();

    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let server_public_key = server_public_key().await?;
    let expected_participants = 2;
    let connected_participants =
        meeting_point::run(&server, server_public_key).await?;
    assert_eq!(expected_participants, connected_participants);

    Ok(())
}
