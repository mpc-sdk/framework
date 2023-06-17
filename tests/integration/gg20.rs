use crate::test_utils::{
    gg20, server_public_key, spawn_server, SERVER,
};
use anyhow::Result;
use serial_test::serial;

/// GG20 keygen and signing.
#[tokio::test]
#[serial]
async fn integration_gg20() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    gg20::run(SERVER, server_public_key).await?;

    Ok(())
}
