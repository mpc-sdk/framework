use anyhow::Result;

use mpc_driver::{
    cggmp::{KeyInitDriver, KeyResharingDriver},
    k256::ecdsa::{SigningKey, VerifyingKey},
    synedrion::{
        KeyResharingInputs, KeyShare, NewHolder, OldHolder,
        PrehashedMessage, RecoverableSignature, TestParams,
        ThresholdKeyShare,
    },
};

use super::{execute_drivers, make_client_sessions, make_signers};
use mpc_protocol::Parameters;
use rand::{rngs::OsRng, Rng};

use sha3::{Digest, Keccak256};

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

    let streams = vec![s_t_1, s_t_2];
    let drivers = vec![
        KeyInitDriver::<TestParams>::new(
            client_t_1_transport.clone(),
            session_t_1,
            &shared_randomness,
            signing_keys.remove(0),
            verifiers.clone(),
        )?,
        KeyInitDriver::<TestParams>::new(
            client_t_2_transport.clone(),
            session_t_2,
            &shared_randomness,
            signing_keys.remove(0),
            verifiers.clone(),
        )?,
    ];

    execute_drivers(streams, drivers).await
}

async fn make_key_resharing(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    t_key_shares: Vec<ThresholdKeyShare<TestParams, VerifyingKey>>,
) -> Result<Vec<ThresholdKeyShare<TestParams, VerifyingKey>>> {
    let n = parameters.parties as usize;
    let t = parameters.threshold as usize;

    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();

    let mut results = make_client_sessions(
        server,
        server_public_key,
        parameters.parties as usize,
    )
    .await?;

    let (client_t_1_transport, session_t_1, s_t_1) =
        results.remove(0);
    let (client_t_2_transport, session_t_2, s_t_2) =
        results.remove(0);
    let (client_t_3_transport, session_t_3, s_t_3) =
        results.remove(0);

    // Prepare for key generation
    let mut transports = vec![
        client_t_1_transport,
        client_t_2_transport,
        client_t_3_transport,
    ];

    let mut sessions = vec![session_t_1, session_t_2, session_t_3];

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
            KeyResharingDriver::<TestParams>::new(
                transport,
                session,
                &shared_randomness,
                signers[idx].clone(),
                verifiers.clone(),
                &inputs,
            )
            .unwrap()
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
            KeyResharingDriver::<TestParams>::new(
                transport,
                session,
                &shared_randomness,
                signers[idx].clone(),
                verifiers.clone(),
                &inputs,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    old_holder_sessions.extend(new_holder_sessions.into_iter());

    let streams = vec![s_t_1, s_t_2, s_t_3];
    let drivers = old_holder_sessions;

    execute_drivers(streams, drivers).await
}
