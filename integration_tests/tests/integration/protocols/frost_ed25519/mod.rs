use crate::test_utils::{server_public_key, spawn_server};
use anyhow::Result;
use mpc_driver::frost::ed25519::ed25519_dalek::{
    SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;

mod dkg;

pub fn make_signers(
    num_parties: usize,
) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| signer.verifying_key().clone())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

/// FROST distributed key generation.
#[tokio::test]
async fn integration_frost_ed25519_dkg_2_3() -> Result<()> {
    // crate::test_utils::init_tracing();
    //

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let addr = rx.await?;
    let server = format!("ws://{}", addr);

    let t = 2;
    let n = 3;

    let server_public_key = server_public_key().await?;
    let (_, key_shares, _) =
        dkg::run_keygen(t, n, &server, server_public_key).await?;

    assert_eq!(n as usize, key_shares.len());

    Ok(())
}
