use anyhow::Result;

use mpc_driver::{
    cggmp::{
        AuxGenDriver, KeyInitDriver, KeyResharingDriver,
        SignatureDriver,
    },
    k256::ecdsa::{SigningKey, VerifyingKey},
    synedrion::{
        AuxInfo, KeyResharingInputs, KeyShare, NewHolder, OldHolder,
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

    run_full_sequence(
        server,
        server_public_key.clone(),
        parameters.clone(),
        &message,
    )
    .await?;

    Ok(())
}

async fn run_full_sequence(
    server: &str,
    server_public_key: Vec<u8>,
    parameters: Parameters,
    prehashed_message: &PrehashedMessage,
) -> Result<()> {
    let n = parameters.parties as usize;
    let t = parameters.threshold as usize;

    let (signers, verifiers) = make_signers(n);

    let rng = &mut OsRng;
    let shared_randomness: [u8; 32] = rng.gen();

    println!("*** KEY INIT ***");

    let key_shares = make_key_init(
        server,
        &server_public_key,
        parameters.clone(),
        &shared_randomness,
        signers.clone(),
    )
    .await?;

    // Convert to t-of-t threshold keyshares
    let t_key_shares = key_shares
        .iter()
        .map(|key_share| key_share.to_threshold_key_share())
        .collect::<Vec<_>>();

    println!("*** KEY RESHARING ***");

    // Reshare to `n` nodes
    let new_t_key_shares = make_key_resharing(
        server,
        &server_public_key,
        parameters.clone(),
        &shared_randomness,
        signers.clone(),
        verifiers.clone(),
        t_key_shares.clone(),
    )
    .await?;

    assert_eq!(
        new_t_key_shares[0].verifying_key(),
        t_key_shares[0].verifying_key()
    );

    println!("*** AUX INFOS ***");

    // Generate auxiliary data
    let aux_infos = make_aux_infos(
        server,
        &server_public_key,
        parameters.clone(),
        &shared_randomness,
        signers.clone(),
        verifiers.clone(),
    )
    .await?;

    let selected_signers =
        vec![signers[0].clone(), signers[2].clone()];
    let selected_parties = vec![verifiers[0], verifiers[2]];
    let selected_key_shares = vec![
        new_t_key_shares[0].to_key_share(&selected_parties),
        new_t_key_shares[2].to_key_share(&selected_parties),
    ];
    let selected_aux_infos =
        vec![aux_infos[0].clone(), aux_infos[2].clone()];

    println!("*** SIGN ***");

    // Generate signatures
    let signatures = make_signatures(
        server,
        &server_public_key,
        parameters.clone(),
        &shared_randomness,
        selected_signers,
        selected_parties,
        selected_key_shares,
        selected_aux_infos,
        prehashed_message,
    )
    .await?;

    assert_eq!(t, signatures.len());

    Ok(())
}

async fn make_key_init(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    shared_randomness: &[u8],
    mut signers: Vec<SigningKey>,
) -> Result<Vec<KeyShare<TestParams, VerifyingKey>>> {
    let verifiers = vec![
        signers.get(0).unwrap().verifying_key().clone(),
        signers.get(1).unwrap().verifying_key().clone(),
    ];

    let results = make_client_sessions(
        server,
        server_public_key,
        parameters.threshold as usize,
    )
    .await?;

    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    for result in results {
        let (transport, session, stream) = result;
        streams.push(stream);
        drivers.push(KeyInitDriver::<TestParams>::new(
            transport,
            session,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?);
    }

    execute_drivers(streams, drivers).await
}

async fn make_key_resharing(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    shared_randomness: &[u8],
    signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    t_key_shares: Vec<ThresholdKeyShare<TestParams, VerifyingKey>>,
) -> Result<Vec<ThresholdKeyShare<TestParams, VerifyingKey>>> {
    let n = parameters.parties as usize;
    let t = parameters.threshold as usize;

    let mut results =
        make_client_sessions(server, server_public_key, n).await?;

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

async fn make_aux_infos(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    shared_randomness: &[u8],
    mut signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
) -> Result<Vec<AuxInfo<TestParams, VerifyingKey>>> {
    let n = parameters.parties as usize;

    let results =
        make_client_sessions(server, server_public_key, n).await?;

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

    execute_drivers(streams, drivers).await
}

async fn make_signatures(
    server: &str,
    server_public_key: &[u8],
    parameters: Parameters,
    shared_randomness: &[u8],
    mut signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    key_shares: Vec<KeyShare<TestParams, VerifyingKey>>,
    aux_info: Vec<AuxInfo<TestParams, VerifyingKey>>,
    prehashed_message: &PrehashedMessage,
) -> Result<Vec<RecoverableSignature>> {
    let t = parameters.threshold as usize;

    let results =
        make_client_sessions(server, server_public_key, t).await?;

    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    for (idx, result) in results.into_iter().enumerate() {
        let (transport, session, stream) = result;
        streams.push(stream);
        drivers.push(SignatureDriver::<TestParams>::new(
            transport,
            session,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
            key_shares.get(idx).unwrap(),
            aux_info.get(idx).unwrap(),
            prehashed_message,
        )?);
    }

    execute_drivers(streams, drivers).await
}
