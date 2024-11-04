use k256::ecdsa::SigningKey;
use mpc_protocol::{decode_keypair, hex};
use rand::{rngs::OsRng, Rng};
use sha3::{Digest, Keccak256};
use std::{fs, path::PathBuf};

const CGGMP_JS: &str = include_str!("../main.js");

const KEYPAIR_P1: &str = include_str!("../../p1.pem");
const KEYPAIR_P2: &str = include_str!("../../p2.pem");
const KEYPAIR_P3: &str = include_str!("../../p3.pem");

const SERVER_URL: &str = "ws://127.0.0.1:8008";
const SERVER_PUBLIC_KEY: &str = include_str!(
    "../../../../../integration_tests/tests/server_public_key.txt"
);

const MSG: &str = "this is the message that is sent out";

fn main() -> anyhow::Result<()> {
    let base_dir = env!("CARGO_MANIFEST_DIR");
    let base_path = PathBuf::from(base_dir);
    let base_path = base_path.parent().expect("parent path");
    let output_dir = base_path.join("tests");

    let rng = &mut OsRng;
    let keygen_session_id_seed: [u8; 32] = rng.gen();
    let sign_session_id_seed: [u8; 32] = rng.gen();

    let file_names = vec!["p1", "p2", "p3"];
    let keypairs = vec![KEYPAIR_P1, KEYPAIR_P2, KEYPAIR_P3];
    let mut keys = Vec::with_capacity(keypairs.len());
    for pem in &keypairs {
        keys.push(decode_keypair(pem)?);
    }

    let signing_keys = vec![
        SigningKey::random(&mut OsRng),
        SigningKey::random(&mut OsRng),
        SigningKey::random(&mut OsRng),
    ];

    let verifiers = signing_keys
        .iter()
        .map(|k| hex::encode(k.verifying_key().to_sec1_bytes()))
        .collect::<Vec<_>>();

    let message = Keccak256::digest(MSG.as_bytes());
    let message = hex::encode(&message);

    let participants: Vec<_> =
        keys.iter().map(|key| key.public_key().to_vec()).collect();

    for (index, ((keypair, signing_key), file_name)) in keypairs
        .into_iter()
        .zip(signing_keys.into_iter())
        .zip(file_names.into_iter())
        .enumerate()
    {
        let noise_key = keys.get(index).unwrap();
        let js = CGGMP_JS
            .replace(
                "${PUBLIC_KEY}",
                &serde_json::to_string(&hex::encode(
                    noise_key.public_key(),
                ))?,
            )
            .replace("${INDEX}", &index.to_string())
            .replace("${MESSAGE}", &message)
            .replace(
                "${PARTICIPANTS}",
                &serde_json::to_string(&participants)?,
            )
            .replace(
                "${KEYGEN_SESSION_ID_SEED}",
                &serde_json::to_string(&hex::encode(
                    &keygen_session_id_seed,
                ))?,
            )
            .replace(
                "${SIGN_SESSION_ID_SEED}",
                &serde_json::to_string(&hex::encode(
                    &sign_session_id_seed,
                ))?,
            )
            .replace(
                "${SIGNER}",
                &serde_json::to_string(&hex::encode(
                    signing_key.to_bytes(),
                ))?,
            )
            .replace(
                "${VERIFIERS}",
                &serde_json::to_string(&verifiers)?,
            )
            .replace("${KEYPAIR}", keypair)
            .replace("${SERVER_URL}", SERVER_URL)
            .replace("${SERVER_PUBLIC_KEY}", SERVER_PUBLIC_KEY);

        let mut js_file = output_dir.join(file_name);
        js_file.set_extension("js");

        fs::write(js_file, js).expect("to write javascript");
    }

    Ok(())
}
