use anyhow::Result;

use mpc_client::{NetworkTransport, Transport};
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
    wait_for_close,
};
use mpc_protocol::{Parameters, SessionState};

use super::{
    execute_drivers, make_client_sessions, make_signers,
    SessionStream,
};
use rand::{rngs::OsRng, Rng};

use sha3::{Digest, Keccak256};

type ClientTransport = (Transport, SessionState, SessionStream);

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

    // Create the collection of network clients
    let clients =
        make_client_sessions(server, &server_public_key, n).await?;

    println!("*** KEY INIT ***");

    let (key_shares, clients) = make_key_init(
        parameters.clone(),
        &shared_randomness,
        signers.clone(),
        clients,
    )
    .await?;

    // Convert to t-of-t threshold keyshares
    let t_key_shares = key_shares
        .iter()
        .map(|key_share| key_share.to_threshold_key_share())
        .collect::<Vec<_>>();

    println!("*** KEY RESHARING ***");

    // Reshare to `n` nodes
    let (new_t_key_shares, clients) = make_key_resharing(
        parameters.clone(),
        &shared_randomness,
        signers.clone(),
        verifiers.clone(),
        t_key_shares.clone(),
        clients,
    )
    .await?;

    assert_eq!(
        new_t_key_shares[0].verifying_key(),
        t_key_shares[0].verifying_key()
    );

    println!("*** AUX INFOS ***");

    // Generate auxiliary data
    let (aux_infos, mut clients) = make_aux_infos(
        parameters.clone(),
        &shared_randomness,
        signers.clone(),
        verifiers.clone(),
        clients,
    )
    .await?;

    for client in clients {
        let (transport, _, mut stream) = client;
        transport.close().await?;
        wait_for_close(&mut stream).await?;
    }

    println!("*** SIGN ***");

    // Create new clients for signing
    let clients =
        make_client_sessions(server, &server_public_key, t).await?;

    let selected_signers =
        vec![signers[0].clone(), signers[2].clone()];
    let selected_parties = vec![verifiers[0], verifiers[2]];
    let selected_key_shares = vec![
        new_t_key_shares[0].to_key_share(&selected_parties),
        new_t_key_shares[2].to_key_share(&selected_parties),
    ];
    let selected_aux_infos =
        vec![aux_infos[0].clone(), aux_infos[2].clone()];

    // Generate signatures
    let (signatures, clients) = make_signatures(
        parameters.clone(),
        &shared_randomness,
        selected_signers,
        selected_parties,
        selected_key_shares,
        selected_aux_infos,
        prehashed_message,
        clients,
    )
    .await?;

    assert_eq!(t, signatures.len());

    for client in clients {
        let (transport, _, mut stream) = client;
        transport.close().await?;
        wait_for_close(&mut stream).await?;
    }

    Ok(())
}

async fn make_key_init(
    parameters: Parameters,
    shared_randomness: &[u8],
    mut signers: Vec<SigningKey>,
    clients: Vec<ClientTransport>,
) -> Result<(
    Vec<KeyShare<TestParams, VerifyingKey>>,
    Vec<ClientTransport>,
)> {
    let t = parameters.threshold as usize;
    let verifiers = vec![
        signers.get(0).unwrap().verifying_key().clone(),
        signers.get(1).unwrap().verifying_key().clone(),
    ];

    let mut t_clients = Vec::new();
    let mut o_clients = Vec::new();
    for (index, client) in clients.into_iter().enumerate() {
        if index < t {
            t_clients.push(client);
        } else {
            o_clients.push(client);
        }
    }

    let mut t_sessions = Vec::new();
    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    for result in t_clients {
        let (transport, session, stream) = result;
        streams.push(stream);
        drivers.push(KeyInitDriver::<TestParams>::new(
            transport,
            session.clone(),
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?);

        t_sessions.push(session);
    }

    let results = execute_drivers(streams, drivers).await?;

    let mut session_output = Vec::new();
    let mut out_clients = Vec::new();
    for result in results {
        let (output, transport, stream) = result;
        session_output.push(output);
        out_clients.push((transport, t_sessions.remove(0), stream));
    }

    out_clients.extend(o_clients);

    Ok((session_output, out_clients))
}

async fn make_key_resharing(
    parameters: Parameters,
    shared_randomness: &[u8],
    signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    t_key_shares: Vec<ThresholdKeyShare<TestParams, VerifyingKey>>,
    mut clients: Vec<ClientTransport>,
) -> Result<(
    Vec<ThresholdKeyShare<TestParams, VerifyingKey>>,
    Vec<ClientTransport>,
)> {
    let n = parameters.parties as usize;
    let t = parameters.threshold as usize;

    let new_holder = NewHolder {
        verifying_key: t_key_shares[0].verifying_key(),
        old_threshold: t_key_shares[0].threshold(),
        old_holders: verifiers[..t].to_vec(),
    };

    let mut streams = Vec::new();
    let mut sessions = Vec::new();

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

            let (transport, session, stream) = clients.remove(0);
            sessions.push(session.clone());
            streams.push(stream);

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

            let (transport, session, stream) = clients.remove(0);
            sessions.push(session.clone());
            streams.push(stream);

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

    let drivers = old_holder_sessions;

    let results = execute_drivers(streams, drivers).await?;

    let mut session_output = Vec::new();
    let mut out_clients = Vec::new();
    for result in results {
        let (output, transport, stream) = result;
        session_output.push(output);
        out_clients.push((transport, sessions.remove(0), stream));
    }

    Ok((session_output, out_clients))
}

async fn make_aux_infos(
    _parameters: Parameters,
    shared_randomness: &[u8],
    mut signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    clients: Vec<ClientTransport>,
) -> Result<(
    Vec<AuxInfo<TestParams, VerifyingKey>>,
    Vec<ClientTransport>,
)> {
    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    let mut sessions = Vec::new();
    for result in clients {
        let (transport, session, stream) = result;
        streams.push(stream);
        sessions.push(session.clone());
        drivers.push(AuxGenDriver::<TestParams>::new(
            transport,
            session,
            &shared_randomness,
            signers.remove(0),
            verifiers.clone(),
        )?);
    }

    let results = execute_drivers(streams, drivers).await?;

    let mut session_output = Vec::new();
    let mut out_clients = Vec::new();
    for result in results {
        let (output, transport, stream) = result;
        session_output.push(output);
        out_clients.push((transport, sessions.remove(0), stream));
    }

    Ok((session_output, out_clients))
}

async fn make_signatures(
    _parameters: Parameters,
    shared_randomness: &[u8],
    mut signers: Vec<SigningKey>,
    verifiers: Vec<VerifyingKey>,
    key_shares: Vec<KeyShare<TestParams, VerifyingKey>>,
    aux_info: Vec<AuxInfo<TestParams, VerifyingKey>>,
    prehashed_message: &PrehashedMessage,
    clients: Vec<ClientTransport>,
) -> Result<(Vec<RecoverableSignature>, Vec<ClientTransport>)> {
    let mut streams = Vec::new();
    let mut drivers = Vec::new();
    let mut sessions = Vec::new();
    for (idx, result) in clients.into_iter().enumerate() {
        let (transport, session, stream) = result;
        streams.push(stream);
        sessions.push(session.clone());
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

    let results = execute_drivers(streams, drivers).await?;

    let mut session_output = Vec::new();
    let mut out_clients = Vec::new();
    for result in results {
        let (output, transport, stream) = result;
        session_output.push(output);
        out_clients.push((transport, sessions.remove(0), stream));
    }

    Ok((session_output, out_clients))
}
