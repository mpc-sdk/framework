use super::{execute_drivers, make_client_sessions, make_signers};
use anyhow::Result;
use mpc_client::NetworkTransport;
use mpc_driver::{
    cggmp::AuxGenDriver, synedrion::TestParams, wait_for_close,
};
use rand::{rngs::OsRng, Rng};

pub async fn run_aux_info(
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
        drivers.push(AuxGenDriver::<TestParams>::new(
            transport,
            session,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?);
    }

    let results = execute_drivers(streams, drivers).await?;
    let mut aux_info = Vec::new();
    let mut transports = Vec::new();
    for result in results {
        let (output, transport, stream) = result;
        aux_info.push(output);
        transports.push((transport, stream));
    }
    assert_eq!(n, aux_info.len());

    for (transport, mut stream) in transports {
        transport.close().await?;
        wait_for_close(&mut stream).await?;
    }

    Ok(())
}
