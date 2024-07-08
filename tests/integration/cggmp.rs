use crate::test_utils::{
    cggmp, server_public_key, spawn_server, SERVER,
};
use anyhow::Result;
use serial_test::serial;

/// CGGMP distributed key generation.
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

/// CGGMP auxiliary info.
#[tokio::test]
#[serial]
async fn integration_cggmp_aux_info() -> Result<()> {
    // crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    cggmp::run_aux_info(SERVER, server_public_key).await?;

    Ok(())
}

/// CGGMP threshold sign.
///
/// This test re-uses the AuxInfo created during DKG for the signing
/// but in the real-world signing would need to generate fresh AuxInfo
/// which is done in the keygen_sign test spec.
#[tokio::test]
#[serial]
async fn integration_cggmp_threshold_sign() -> Result<()> {
    // crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    cggmp::run_threshold_sign(SERVER, server_public_key).await?;

    Ok(())
}

/// CGGMP DKG followed by signing.
#[tokio::test]
#[serial]
async fn integration_cggmp_keygen_sign() -> Result<()> {
    // crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;
    cggmp::run_keygen_sign(SERVER, server_public_key).await?;

    Ok(())
}
