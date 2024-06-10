use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::collections::HashMap;

use mpc_driver::{
    cggmp::KeyGenDriver,
    k256::ecdsa::VerifyingKey,
    synedrion::{KeyShare, TestParams},
    Driver, SessionHandler, SessionInitiator, SessionParticipant,
};

use super::{
    drive_stream_sessions, make_client_sessions, make_signers,
};
use crate::test_utils::new_client;
use mpc_client::{NetworkTransport, Transport};
use mpc_protocol::Keypair;
use rand::{rngs::OsRng, Rng};

type KeyShareOutput = KeyShare<TestParams, VerifyingKey>;

pub async fn run_keygen(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let n = 3;
    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();

    let key_shares = cggmp_keygen(
        server,
        &server_public_key,
        &shared_randomness,
        n,
    )
    .await?;

    assert_eq!(3, key_shares.len());

    Ok(())
}

/// Create a new session and then perform distributed key generation.
async fn cggmp_keygen(
    server: &str,
    server_public_key: &[u8],
    shared_randomness: &[u8],
    n: usize,
) -> Result<HashMap<Vec<u8>, KeyShareOutput>> {
    let (mut signers, verifiers) = make_signers(n);

    let mut results =
        make_client_sessions(server, server_public_key, n).await?;

    // Prepare for key generation
    let (client_i_transport, session_i, mut s_i) = results.remove(0);
    let (client_p_1_transport, session_p_1, mut s_p_1) =
        results.remove(0);
    let (client_p_2_transport, session_p_2, mut s_p_2) =
        results.remove(0);

    let mut keygen_i = KeyGenDriver::<TestParams>::new(
        client_i_transport.clone(),
        session_i,
        shared_randomness,
        signers.remove(0),
        verifiers.clone(),
    )?;
    let mut keygen_p_1 = KeyGenDriver::<TestParams>::new(
        client_p_1_transport.clone(),
        session_p_1,
        shared_randomness,
        signers.remove(0),
        verifiers.clone(),
    )?;
    let mut keygen_p_2 = KeyGenDriver::<TestParams>::new(
        client_p_2_transport.clone(),
        session_p_2,
        shared_randomness,
        signers.remove(0),
        verifiers.clone(),
    )?;

    // Each party starts key generation protocol.
    keygen_i.execute().await?;
    keygen_p_1.execute().await?;
    keygen_p_2.execute().await?;

    let mut key_shares: HashMap<Vec<u8>, KeyShareOutput> =
        HashMap::new();

    loop {
        if key_shares.len() == 3 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_share) =
                            keygen_i.handle_event(event).await? {
                            key_shares.insert(
                                client_i_transport.public_key().to_vec(),
                                key_share.0);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_share) =
                            keygen_p_1.handle_event(event).await? {
                            key_shares.insert(
                                client_p_1_transport.public_key().to_vec(),
                                key_share.0);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_share) =
                            keygen_p_2.handle_event(event).await? {
                            key_shares.insert(
                                client_p_2_transport.public_key().to_vec(),
                                key_share.0);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(key_shares)
}
