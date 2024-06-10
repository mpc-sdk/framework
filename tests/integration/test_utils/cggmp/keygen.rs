use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::collections::HashMap;

use mpc_driver::{
    cggmp::KeyGenDriver,
    k256::ecdsa::VerifyingKey,
    synedrion::{KeyShare, TestParams},
    Driver, SessionHandler, SessionInitiator, SessionParticipant,
};

use super::{drive_stream_sessions, make_signers};
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

    let (key_shares, _transport_keypairs) = cggmp_keygen(
        server,
        server_public_key.clone(),
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
    server_public_key: Vec<u8>,
    shared_randomness: &[u8],
    n: usize,
) -> Result<(HashMap<Vec<u8>, KeyShareOutput>, Vec<Keypair>)> {
    let (mut signers, verifiers) = make_signers(n);

    // Create new clients
    let (client_i, event_loop_i, initiator_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (client_p_1, event_loop_p_1, participant_key_1) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let (client_p_2, event_loop_p_2, participant_key_2) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let keypairs = vec![
        initiator_key.clone(),
        participant_key_1.clone(),
        participant_key_2.clone(),
    ];

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_1_transport: Transport = client_p_1.into();
    let mut client_p_2_transport: Transport = client_p_2.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_1_transport.connect().await?;
    client_p_2_transport.connect().await?;

    // Event loop streams
    let s_i = event_loop_i.run();
    let s_p_1 = event_loop_p_1.run();
    let s_p_2 = event_loop_p_2.run();

    let session_participants = vec![
        participant_key_1.public_key().to_vec(),
        participant_key_2.public_key().to_vec(),
    ];

    let client_i_session = SessionInitiator::new(
        client_i_transport,
        session_participants,
    );
    let client_p_1_session =
        SessionParticipant::new(client_p_1_transport);
    let client_p_2_session =
        SessionParticipant::new(client_p_2_transport);

    let mut results = drive_stream_sessions(
        vec![s_i, s_p_1, s_p_2],
        vec![
            SessionHandler::Initiator(client_i_session),
            SessionHandler::Participant(client_p_1_session),
            SessionHandler::Participant(client_p_2_session),
        ],
    )
    .await?;

    /*
    // Prepare the sessions for each party
    loop {
        if sessions.len() == 3 {
            break;
        }

        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;

                        if let Some(session) =
                            client_i_session.handle_event(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_p_1_session.handle_event(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_p_2_session.handle_event(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    */

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

    Ok((key_shares, keypairs))
}
