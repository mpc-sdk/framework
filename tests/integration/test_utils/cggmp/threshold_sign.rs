use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::collections::HashMap;

use mpc_driver::{
    cggmp::{
        self, AuxGenDriver, KeyGenDriver, KeyInitDriver,
        SignatureDriver,
    },
    k256::{
        self,
        ecdsa::{SigningKey, VerifyingKey},
    },
    synedrion::{
        KeyShare, PrehashedMessage, RecoverableSignature, TestParams,
    },
    Driver, SessionEventHandler, SessionInitiator,
    SessionParticipant,
};

use mpc_client::{NetworkTransport, Transport};
use mpc_protocol::{Keypair, Parameters, SessionState};
use rand::{rngs::OsRng, Rng};

use sha3::{Digest, Keccak256};

use crate::test_utils::{new_client, new_client_with_keypair};

type KeyShareOutput = KeyShare<TestParams, VerifyingKey>;

pub async fn run_threshold_sign(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let t = 2;
    let n = 3;

    // 2 of 3
    let parameters = Parameters {
        parties: n,
        threshold: t,
    };

    let message = "this is the message that is sent out";
    let message: PrehashedMessage =
        Keccak256::digest(message.as_bytes())
            .as_slice()
            .try_into()?;

    let signatures = cggmp_sign(
        server,
        server_public_key.clone(),
        parameters.clone(),
        &message,
    )
    .await?;

    // assert_eq!(2, signatures.len());

    Ok(())
}

/// Create a new session and then perform
/// signature generation
async fn cggmp_sign(
    server: &str,
    server_public_key: Vec<u8>,
    parameters: Parameters,
    prehashed_message: &PrehashedMessage,
) -> Result<()> {
    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();
    let mut signing_keys = Vec::new();
    for _ in 0..parameters.parties {
        signing_keys.push(k256::ecdsa::SigningKey::random(rng));
    }

    let key_shares = make_key_init(
        server,
        server_public_key,
        parameters.clone(),
        signing_keys.clone(),
    )
    .await?;

    // Convert to t-of-t threshold keyshares
    let t_key_shares = key_shares
        .iter()
        .map(|key_share| key_share.to_threshold_key_share())
        .collect::<Vec<_>>();

    Ok(())

    /*
    let signing_key_1 = signing_keys.remove(0);
    let signing_key_3 = signing_keys.remove(0);

    let verifiers: Vec<VerifyingKey> = vec![
        signing_key_1.verifying_key().clone(),
        signing_key_3.verifying_key().clone(),
    ];

    let initiator_key = keypairs.remove(0);
    let participant_key_2 = keypairs.pop().unwrap();
    let sign_participants =
        vec![participant_key_2.public_key().to_vec()];

    // Create new clients for signature generation
    let (client_i, event_loop_i) =
        new_client_with_keypair::<anyhow::Error>(
            server,
            server_public_key.clone(),
            initiator_key,
        )
        .await?;
    let (client_p_2, event_loop_p_2) =
        new_client_with_keypair::<anyhow::Error>(
            server,
            server_public_key.clone(),
            participant_key_2,
        )
        .await?;

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_2_transport: Transport = client_p_2.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_2_transport.connect().await?;

    let mut s_i = event_loop_i.run();
    let mut s_p_2 = event_loop_p_2.run();

    let mut sessions: Vec<SessionState> = Vec::new();

    let mut client_i_session =
        SessionInitiator::new(client_i_transport, sign_participants);
    let mut client_p_2_session =
        SessionParticipant::new(client_p_2_transport);

    // Prepare the sessions for each party
    loop {
        if sessions.len() == 2 {
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

    // Prepare for aux info generation
    let client_i_transport: Transport = client_i_session.into();
    let client_p_2_transport: Transport = client_p_2_session.into();

    let session_i = sessions.remove(0);
    let session_p_2 = sessions.remove(0);

    let mut aux_i = AuxGenDriver::<TestParams>::new(
        client_i_transport.clone(),
        session_i.clone(),
        shared_randomness,
        signing_key_1.clone(),
        verifiers.clone(),
    )?;
    let mut aux_p_2 = AuxGenDriver::<TestParams>::new(
        client_p_2_transport.clone(),
        session_p_2.clone(),
        shared_randomness,
        signing_key_3.clone(),
        verifiers.clone(),
    )?;

    // Each party starts aux info generation.
    aux_i.execute().await?;
    aux_p_2.execute().await?;

    let mut aux_infos = Vec::new();

    loop {
        if aux_infos.len() == 2 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(aux) =
                            aux_i.handle_event(event).await? {
                            aux_infos.insert(0, aux);

                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(aux) =
                            aux_p_2.handle_event(event).await? {
                            aux_infos.push(aux);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    let aux_info_i = aux_infos.remove(0);
    let aux_info_p_2 = aux_infos.remove(0);

    let key_share_i = key_shares.get(0).unwrap();
    let key_share_p_2 = key_shares.get(2).unwrap();

    let mut sign_i = SignatureDriver::new(
        client_i_transport.clone(),
        session_i,
        shared_randomness,
        signing_key_1.clone(),
        verifiers.clone(),
        key_share_i,
        &aux_info_i,
        prehashed_message,
    )?;
    let mut sign_p_2 = SignatureDriver::new(
        client_p_2_transport.clone(),
        session_p_2,
        shared_randomness,
        signing_key_3.clone(),
        verifiers.clone(),
        key_share_p_2,
        &aux_info_p_2,
        prehashed_message,
    )?;

    // Each party starts signature generation.
    sign_i.execute().await?;
    sign_p_2.execute().await?;

    let mut signatures = Vec::new();

    loop {
        if signatures.len() == 2 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(signature) =
                            sign_i.handle_event(event).await? {
                            signatures.push(signature);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(signature) =
                            sign_p_2.handle_event(event).await? {
                            signatures.push(signature);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(signatures)
      */
}

async fn make_key_init(
    server: &str,
    server_public_key: Vec<u8>,
    parameters: Parameters,
    mut signing_keys: Vec<SigningKey>,
) -> Result<Vec<KeyShare<TestParams, VerifyingKey>>> {
    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();
    let verifiers = vec![
        signing_keys.get(0).unwrap().verifying_key().clone(),
        signing_keys.get(1).unwrap().verifying_key().clone(),
    ];

    // Create new clients
    let (client_t_1, event_loop_t_1, _key_t_1) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (client_t_2, event_loop_t_2, key_t_2) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let mut client_t_1_transport: Transport = client_t_1.into();
    let mut client_t_2_transport: Transport = client_t_2.into();

    // Each client handshakes with the server
    client_t_1_transport.connect().await?;
    client_t_2_transport.connect().await?;

    // Event loop streams
    let mut s_t_1 = event_loop_t_1.run();
    let mut s_t_2 = event_loop_t_2.run();

    let session_participants = vec![key_t_2.public_key().to_vec()];

    let mut client_t_1_session = SessionInitiator::new(
        client_t_1_transport,
        session_participants,
    );
    let mut client_t_2_session =
        SessionParticipant::new(client_t_2_transport);

    let mut sessions: Vec<SessionState> = Vec::new();

    // Prepare the sessions for each party
    loop {
        if sessions.len() == parameters.threshold as usize {
            break;
        }

        select! {
            event = s_t_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;

                        if let Some(session) =
                            client_t_1_session.handle_event(event).await? {
                            sessions.insert(0, session);
                        }
                    }
                    _ => {}
                }
            },
            event = s_t_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_t_2_session.handle_event(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    // Prepare for key generation
    let client_t_1_transport: Transport = client_t_1_session.into();
    let client_t_2_transport: Transport = client_t_2_session.into();

    let session_t_1 = sessions.remove(0);
    let session_t_2 = sessions.remove(0);

    let mut key_init_t_1 = KeyInitDriver::<TestParams>::new(
        client_t_1_transport.clone(),
        session_t_1,
        &shared_randomness,
        signing_keys.remove(0),
        verifiers.clone(),
    )?;
    let mut key_init_t_2 = KeyInitDriver::<TestParams>::new(
        client_t_2_transport.clone(),
        session_t_2,
        &shared_randomness,
        signing_keys.remove(0),
        verifiers.clone(),
    )?;

    // Each party starts key generation protocol.
    key_init_t_1.execute().await?;
    key_init_t_2.execute().await?;

    println!("Sessions prepare for make key init...");

    let mut results = Vec::new();

    loop {
        if results.len() == 2 {
            break;
        }
        select! {
            event = s_t_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_init) =
                            key_init_t_1.handle_event(event).await? {
                            results.push(key_init);
                        }
                    }
                    _ => {}
                }
            },
            event = s_t_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_init) =
                            key_init_t_2.handle_event(event).await? {
                            results.push(key_init);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(results)
}
