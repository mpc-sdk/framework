use anyhow::Result;
use mpc_driver::{
    k256::ecdsa::{self, signature::hazmat::PrehashVerifier},
    keygen, sign,
    synedrion::SessionId,
    Participant, PartyOptions, PrivateKey, Protocol, ServerOptions,
    SessionOptions,
};
use mpc_protocol::{generate_keypair, Parameters};
use rand::{rngs::OsRng, Rng};

use super::{make_signers, make_signing_message};

pub async fn run_dkg_sign_2_3(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let n = 3;
    let t = 2;
    run_dkg_sign(n, t, server, server_public_key).await
}

async fn run_dkg_sign(
    n: u16,
    t: u16,
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
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
                Participant::new(signer, party)?,
                keygen_session_id.clone(),
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

    let first_share = key_shares.remove(0);
    let PrivateKey::Cggmp(first_private) = &first_share.private_key;
    let vkey = first_private.verifying_key().clone();

    let selected_key_shares =
        vec![first_share, key_shares.remove(key_shares.len() - 1)];
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
                Participant::new(signer, party)?,
                sign_session_id.clone(),
                &key_share.private_key,
                &message,
            )
            .await?;
            Ok::<_, anyhow::Error>(signature)
        }));
    }

    // Gather the signatures
    let mut signatures = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    for result in results {
        signatures.push(result?);
    }

    assert_eq!(t as usize, signatures.len());

    let mut ecdsa_signatures: Vec<(
        ecdsa::Signature,
        ecdsa::RecoveryId,
    )> = Vec::with_capacity(signatures.len());
    for sig in signatures {
        ecdsa_signatures.push(sig.try_into()?);
    }
    for (sig, rec_id) in ecdsa_signatures {
        // Check that the signature can be verified
        vkey.verify_prehash(&message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key =
            ecdsa::VerifyingKey::recover_from_prehash(
                &message, &sig, rec_id,
            )
            .unwrap();
        assert_eq!(recovered_key, vkey);
    }

    Ok(())
}
