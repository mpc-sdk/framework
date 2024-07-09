use anyhow::Result;
use mpc_driver::{
    keygen, sign, synedrion::SessionId, PartyOptions, Protocol,
    ServerOptions, SessionOptions,
};
use mpc_protocol::{generate_keypair, Parameters};
use rand::{rngs::OsRng, Rng};

use super::{make_signers, make_signing_message};

pub async fn run_keygen_sign(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let n = 3;
    let t = 2;
    let params = Parameters {
        parties: n,
        threshold: t,
    };
    let (signers, verifiers) = make_signers(n as usize);
    let message = make_signing_message()?;
    let server = ServerOptions {
        server_url: server.to_owned(),
        server_public_key: server_public_key.clone(),
        pattern: None,
    };

    let rng = &mut OsRng;
    let keygen_session_id: [u8; 32] = rng.gen();
    let keygen_session_id = SessionId::from_seed(&keygen_session_id);

    let mut session_options = Vec::new();
    let mut public_keys = Vec::new();
    let mut keypairs = Vec::new();

    for _ in 0..n {
        let keypair = generate_keypair()?;
        keypairs.push(keypair.clone());
        public_keys.push(keypair.public_key().to_vec());

        session_options.push(SessionOptions {
            protocol: Protocol::Cggmp,
            keypair,
            parameters: params.clone(),
            server: server.clone(),
        });
    }

    let mut tasks = Vec::new();

    for (index, (opts, signer)) in session_options
        .into_iter()
        .zip(signers.clone().into_iter())
        .enumerate()
    {
        let participants =
            public_keys.iter().cloned().collect::<Vec<_>>();
        let is_initiator = index == 0;
        let public_key = participants.get(index).unwrap().to_vec();

        let party = PartyOptions::new(
            public_key,
            participants,
            is_initiator,
            verifiers.clone(),
        )?;

        tasks.push(tokio::task::spawn(async move {
            let key_share = keygen(
                opts,
                party,
                keygen_session_id.clone(),
                signer,
            )
            .await?;
            Ok::<_, anyhow::Error>(key_share)
        }));
    }

    // Gather the key shares
    let mut key_shares = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    for result in results {
        key_shares.push(result?);
    }

    // Prepare data for signing
    let sign_session_id: [u8; 32] = rng.gen();
    let sign_session_id = SessionId::from_seed(&sign_session_id);

    let selected_signers =
        vec![signers[0].clone(), signers[2].clone()];
    let selected_verifiers = selected_signers
        .iter()
        .map(|s| s.verifying_key().clone())
        .collect::<Vec<_>>();
    let selected_key_shares = vec![
        key_shares.remove(0),
        key_shares.remove(key_shares.len() - 1),
    ];
    let public_keys = vec![
        keypairs.get(0).unwrap().public_key().to_owned(),
        keypairs.get(2).unwrap().public_key().to_owned(),
    ];

    let session_options = vec![
        SessionOptions {
            protocol: Protocol::Cggmp,
            keypair: keypairs.get(0).unwrap().clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
        SessionOptions {
            protocol: Protocol::Cggmp,
            keypair: keypairs.get(2).unwrap().clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
    ];

    let mut tasks = Vec::new();
    for (index, ((opts, key_share), signer)) in session_options
        .into_iter()
        .zip(selected_key_shares.into_iter())
        .zip(selected_signers.into_iter())
        .enumerate()
    {
        let participants =
            public_keys.iter().cloned().collect::<Vec<_>>();
        let is_initiator = index == 0;
        let public_key = participants.get(index).unwrap().to_vec();

        let party = PartyOptions::new(
            public_key,
            participants,
            is_initiator,
            selected_verifiers.clone(),
        )?;

        tasks.push(tokio::task::spawn(async move {
            let signature = sign(
                opts,
                party,
                sign_session_id.clone(),
                signer,
                &key_share.private_key,
                &message,
            )
            .await?;
            Ok::<_, anyhow::Error>(signature)
        }));
    }

    Ok(())
}
