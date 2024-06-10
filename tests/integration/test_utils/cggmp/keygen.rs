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
    let mut results =
        make_client_sessions(server, &server_public_key, n).await?;

    // Prepare for key generation
    let (client_i_transport, session_i, s_i) = results.remove(0);
    let (client_p_1_transport, session_p_1, s_p_1) =
        results.remove(0);
    let (client_p_2_transport, session_p_2, s_p_2) =
        results.remove(0);

    let streams = vec![s_i, s_p_1, s_p_2];
    let drivers = vec![
        KeyGenDriver::<TestParams>::new(
            client_i_transport.clone(),
            session_i,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?,
        KeyGenDriver::<TestParams>::new(
            client_p_1_transport.clone(),
            session_p_1,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?,
        KeyGenDriver::<TestParams>::new(
            client_p_2_transport.clone(),
            session_p_2,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?,
    ];

    let key_shares = execute_drivers(streams, drivers).await?;
    assert_eq!(3, key_shares.len());

    Ok(())
}
