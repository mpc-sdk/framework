use super::dkg::run_keygen;
use anyhow::Result;
use mpc_driver::{
    frost::ed25519::{
        ed25519_dalek::SigningKey, sign, KeyShare, Participant,
        PartyOptions,
    },
    frost::frost_ed25519::keys,
    ServerOptions, SessionOptions,
};
use mpc_protocol::{generate_keypair, Parameters, SessionId};
use std::collections::BTreeMap;

use super::make_signing_message;

pub async fn run_dkg_sign(
    t: u16,
    n: u16,
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let (server, key_shares, signers) =
        run_keygen(t, n, server, server_public_key).await?;

    sign_t_2(t, n, server, key_shares, signers).await?;

    Ok(())
}

pub(super) async fn sign_t_2(
    t: u16,
    n: u16,
    server: ServerOptions,
    mut key_shares: Vec<KeyShare>,
    signers: Vec<SigningKey>,
) -> Result<()> {
    // Prepare group public key for verification after signing
    let mut verifying_keys = key_shares
        .iter()
        .map(|k| {
            (
                k.0.identifier().clone(),
                k.0.verifying_share().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let verifying_key =
        key_shares.first().unwrap().0.verifying_key().to_owned();
    let pubkey_package =
        keys::PublicKeyPackage::new(verifying_keys, verifying_key);

    let params = Parameters {
        parties: n,
        threshold: t,
    };

    let message = make_signing_message();

    let mut keypairs = Vec::new();

    for _ in 0..t {
        let keypair = generate_keypair()?;
        keypairs.push(keypair.clone());
    }

    let sign_session_id = SessionId::new_v4();

    let selected_signers = vec![
        signers.first().unwrap().clone(),
        signers.last().unwrap().clone(),
    ];
    let selected_verifiers = selected_signers
        .iter()
        .map(|s| s.verifying_key().clone())
        .collect::<Vec<_>>();

    let first_share = key_shares.remove(0);

    let selected_key_shares =
        vec![first_share, key_shares.remove(key_shares.len() - 1)];
    let public_keys = vec![
        keypairs.first().unwrap().public_key().to_owned(),
        keypairs.last().unwrap().public_key().to_owned(),
    ];

    let session_options = vec![
        SessionOptions {
            keypair: keypairs.first().unwrap().clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
        SessionOptions {
            keypair: keypairs.last().unwrap().clone(),
            parameters: params.clone(),
            server: server.clone(),
        },
    ];

    let identifiers = selected_key_shares
        .iter()
        .map(|s| s.0.identifier().clone())
        .collect::<Vec<_>>();

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

        let verifier = signer.verifying_key().clone();
        let participant = Participant::new(signer, verifier, party)?;
        let msg = message.clone();
        let ids = identifiers.clone();

        tasks.push(tokio::task::spawn(async move {
            let signature = sign(
                opts,
                participant,
                sign_session_id.clone(),
                ids,
                key_share,
                msg,
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

    for sig in &signatures {
        // Check that the threshold signature can be verified by
        // the group public key (the verification key).
        pubkey_package.verifying_key().verify(&message, &sig)?;
        // Check that the threshold signature can be verified by
        // the group public key (the verification key) from
        // KeyPackage.verifying_key
        for key_share in &key_shares {
            key_share.1.verifying_key().verify(&message, sig)?;
        }
    }

    Ok(())
}
