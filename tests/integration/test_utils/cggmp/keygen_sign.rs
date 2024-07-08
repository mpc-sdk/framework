use anyhow::Result;
use mpc_driver::{
    keygen, synedrion::SessionId, Protocol, ServerOptions,
    SessionOptions,
};
use mpc_protocol::{generate_keypair, Parameters};
use rand::{rngs::OsRng, Rng};
use std::collections::BTreeSet;

use super::make_signers;

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

    let rng = &mut OsRng;
    let keygen_session_id: [u8; 32] = rng.gen();
    let keygen_session_id = SessionId::from_seed(&keygen_session_id);

    let mut session_options = Vec::new();
    let mut public_keys = Vec::new();

    for _ in 0..n {
        let keypair = generate_keypair()?;
        public_keys.push(keypair.public_key().to_vec());

        session_options.push(SessionOptions {
            protocol: Protocol::Cggmp,
            keypair,
            parameters: params.clone(),
            server: ServerOptions {
                server_url: server.to_owned(),
                server_public_key: server_public_key.clone(),
                pattern: None,
            },
        });
    }

    let mut tasks = Vec::new();

    for (index, (opts, signer)) in session_options
        .into_iter()
        .zip(signers.into_iter())
        .enumerate()
    {
        let participants = if index == 0 {
            let participants = public_keys
                .iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>();
            Some(participants)
        } else {
            None
        };
        let verifying_keys = verifiers.clone();
        tasks.push(tokio::task::spawn(async move {
            let key_share = keygen(
                opts,
                participants,
                keygen_session_id.clone(),
                signer,
                verifying_keys,
            )
            .await?;
            Ok::<_, anyhow::Error>(key_share)
        }));
    }

    let mut key_shares = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    for result in results {
        key_shares.push(result?);
    }

    /*
    let selected_signers =
        vec![signers[0].clone(), signers[2].clone()];
    let selected_parties = vec![verifiers[0], verifiers[2]];
    let selected_parties_set =
        BTreeSet::from([verifiers[0], verifiers[2]]);
    */

    /*
    let selected_key_shares = vec![
        key_shares[0].to_key_share(&selected_parties_set),
        key_shares[2].to_key_share(&selected_parties_set),
    ];
    */

    /*
    let selected_aux_infos =
        vec![aux_infos[0].clone(), aux_infos[2].clone()];
    */

    /*
    let sign_session_id: [u8; 32] = rng.gen();
    let sign_session_id = SessionId::from_seed(&sign_session_id);
    */

    Ok(())
}
