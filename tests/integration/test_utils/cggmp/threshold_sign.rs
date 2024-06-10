use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::collections::HashMap;

use mpc_driver::{
    cggmp::{
        self, AuxGenDriver, KeyGenDriver, KeyInitDriver,
        KeyResharingDriver, SignatureDriver,
    },
    k256::{
        self,
        ecdsa::{SigningKey, VerifyingKey},
    },
    synedrion::{
        KeyResharingInputs, KeyShare, NewHolder, OldHolder,
        PrehashedMessage, RecoverableSignature, TestParams,
        ThresholdKeyShare,
    },
    Driver, SessionEventHandler, SessionInitiator,
    SessionParticipant,
};

use super::{make_client_sessions, make_signers};
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
    let n = parameters.parties as usize;
    let t = parameters.threshold as usize;

    let (signers, verifiers) = make_signers(n);

    let key_shares = make_key_init(
        server,
        &server_public_key,
        parameters.clone(),
        signers.clone(),
    )
    .await?;

    // Convert to t-of-t threshold keyshares
    let t_key_shares = key_shares
        .iter()
        .map(|key_share| key_share.to_threshold_key_share())
        .collect::<Vec<_>>();

    let new_key_shares = make_key_resharing(
        server,
        &server_public_key,
        parameters.clone(),
        signers.clone(),
        verifiers.clone(),
        t_key_shares,
    )
    .await?;

    Ok(())
}

async fn make_key_init(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    mut signing_keys: Vec<SigningKey>,
) -> Result<Vec<KeyShare<TestParams, VerifyingKey>>> {
    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();

    let verifiers = vec![
        signing_keys.get(0).unwrap().verifying_key().clone(),
        signing_keys.get(1).unwrap().verifying_key().clone(),
    ];

    let mut results = make_client_sessions(
        server,
        server_public_key,
        parameters.threshold as usize,
    )
    .await?;

    let (client_t_1_transport, session_t_1, mut s_t_1) =
        results.remove(0);
    let (client_t_2_transport, session_t_2, mut s_t_2) =
        results.remove(0);

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

async fn make_key_resharing(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    mut signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    t_key_shares: Vec<ThresholdKeyShare<TestParams, VerifyingKey>>,
) -> Result<Vec<KeyShare<TestParams, VerifyingKey>>> {
    let n = parameters.parties as usize;
    let t = parameters.threshold as usize;

    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();

    // Create new clients
    let (client_t_1, event_loop_t_1, _key_t_1) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.to_vec(),
        )
        .await?;
    let (client_t_2, event_loop_t_2, key_t_2) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.to_vec(),
        )
        .await?;
    let (client_t_3, event_loop_t_3, key_t_3) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.to_vec(),
        )
        .await?;

    let mut client_t_1_transport: Transport = client_t_1.into();
    let mut client_t_2_transport: Transport = client_t_2.into();
    let mut client_t_3_transport: Transport = client_t_3.into();

    // Each client handshakes with the server
    client_t_1_transport.connect().await?;
    client_t_2_transport.connect().await?;
    client_t_3_transport.connect().await?;

    // Event loop streams
    let mut s_t_1 = event_loop_t_1.run();
    let mut s_t_2 = event_loop_t_2.run();
    let mut s_t_3 = event_loop_t_3.run();

    let session_participants = vec![
        key_t_2.public_key().to_vec(),
        key_t_3.public_key().to_vec(),
    ];

    let mut client_t_1_session = SessionInitiator::new(
        client_t_1_transport,
        session_participants,
    );
    let mut client_t_2_session =
        SessionParticipant::new(client_t_2_transport);
    let mut client_t_3_session =
        SessionParticipant::new(client_t_3_transport);

    let mut sessions: Vec<SessionState> = Vec::new();

    // Prepare the sessions for each party
    loop {
        if sessions.len() == parameters.parties as usize {
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
            event = s_t_3.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_t_3_session.handle_event(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    // Prepare for key generation
    let mut transports = vec![
        client_t_1_session.into(),
        client_t_2_session.into(),
        client_t_3_session.into(),
    ];

    let new_holder = NewHolder {
        verifying_key: t_key_shares[0].verifying_key(),
        old_threshold: t_key_shares[0].threshold(),
        old_holders: verifiers[..t].to_vec(),
    };

    // Old holders' sessions (which will also hold the newly reshared parts)
    let mut old_holder_sessions = (0..t)
        .map(|idx| {
            let inputs = KeyResharingInputs {
                old_holder: Some(OldHolder {
                    key_share: t_key_shares[idx].clone(),
                }),
                new_holder: Some(new_holder.clone()),
                new_holders: verifiers.clone(),
                new_threshold: t,
            };

            let transport = transports.remove(0);
            let session = sessions.remove(0);
            KeyResharingDriver::new(
                transport,
                session,
                &shared_randomness,
                signers[idx].clone(),
                verifiers.clone(),
                &inputs,
            )
        })
        .collect::<Vec<_>>();

    // New holders' sessions
    let new_holder_sessions = (t..n)
        .map(|idx| {
            let inputs = KeyResharingInputs {
                old_holder: None,
                new_holder: Some(new_holder.clone()),
                new_holders: verifiers.clone(),
                new_threshold: t,
            };

            let transport = transports.remove(0);
            let session = sessions.remove(0);
            KeyResharingDriver::new(
                transport,
                session,
                &shared_randomness,
                signers[idx].clone(),
                verifiers.clone(),
                &inputs,
            )
        })
        .collect::<Vec<_>>();

    old_holder_sessions.extend(new_holder_sessions.into_iter());

    todo!();
}
