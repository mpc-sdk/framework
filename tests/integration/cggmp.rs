use crate::test_utils::{
    cggmp, server_public_key, spawn_server, SERVER,
};
use anyhow::Result;
use serial_test::serial;

/// CGGMP keygen and signing.
#[tokio::test]
#[serial]
async fn integration_cggmp_keygen() -> Result<()> {
    // crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    cggmp::run_keygen(SERVER, server_public_key).await?;

    Ok(())
}
