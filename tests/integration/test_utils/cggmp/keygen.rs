use super::{execute_drivers, make_client_sessions, make_signers};
use anyhow::Result;
use mpc_driver::{cggmp::KeyGenDriver, synedrion::TestParams};
use rand::{rngs::OsRng, Rng};

pub async fn run_keygen(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let n = 3;
    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();

    let (mut signers, verifiers) = make_signers(n);
    let results =
        make_client_sessions(server, &server_public_key, n).await?;

    // Prepare for key generation
    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    for result in results {
        let (transport, session, stream) = result;
        streams.push(stream);
        drivers.push(KeyGenDriver::<TestParams>::new(
            transport,
            session,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?);
    }

    let key_shares = execute_drivers(streams, drivers).await?;
    assert_eq!(n, key_shares.len());

    Ok(())
}
