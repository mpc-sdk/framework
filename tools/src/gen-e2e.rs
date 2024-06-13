use mpc_protocol::{decode_keypair, hex};
use sha3::{Digest, Keccak256};
use std::{fs, path::PathBuf};

const CGGMP_JS: &str =
    include_str!("../../tests/e2e/cggmp/template.js");
const CGGMP_HTML: &str =
    include_str!("../../tests/e2e/cggmp/template.html");

const KEYPAIR_P1: &str = include_str!("../../tests/e2e/p1.pem");
const KEYPAIR_P2: &str = include_str!("../../tests/e2e/p2.pem");
const KEYPAIR_P3: &str = include_str!("../../tests/e2e/p3.pem");

const SERVER_URL: &str = "ws://127.0.0.1:8008";
const SERVER_PUBLIC_KEY: &str =
    include_str!("../../tests/server_public_key.txt");

const MSG: &str = "this is the message that is sent out";

fn main() {
    let base_dir = env!("CARGO_MANIFEST_DIR");
    let base_path = PathBuf::from(base_dir);
    let base_path = base_path.parent().expect("parent path");
    let output_dir =
        base_path.join("tests").join("e2e").join("cggmp");

    let file_names = vec!["p1", "p2", "p3"];
    let keypairs = vec![KEYPAIR_P1, KEYPAIR_P2, KEYPAIR_P3];

    let message = Keccak256::digest(MSG.as_bytes());
    let message = hex::encode(&message);

    let joiners = vec![KEYPAIR_P2, KEYPAIR_P3];
    let joiners: Vec<_> = joiners
        .into_iter()
        .map(|pem| {
            hex::encode(decode_keypair(pem).unwrap().public_key())
        })
        .collect();

    let signing_joiners = vec![KEYPAIR_P3];
    let signing_joiners: Vec<_> = signing_joiners
        .into_iter()
        .map(|pem| {
            hex::encode(decode_keypair(pem).unwrap().public_key())
        })
        .collect();

    for (index, (keypair, file_name)) in
        keypairs.iter().zip(file_names.iter()).enumerate()
    {
        let participants = if index == 0 {
            format!("{:#?}", joiners)
        } else {
            "null".to_owned()
        };

        let signing_participants = if index == 0 {
            format!("{:#?}", signing_joiners)
        } else {
            "null".to_owned()
        };

        let js = CGGMP_JS
            .replace("${INDEX}", &index.to_string())
            .replace("${MESSAGE}", &message)
            .replace("${PARTICIPANTS}", &participants)
            .replace("${SIGNING_PARTICIPANTS}", &signing_participants)
            .replace("${KEYPAIR}", keypair)
            .replace("${SERVER_URL}", SERVER_URL)
            .replace("${SERVER_PUBLIC_KEY}", SERVER_PUBLIC_KEY);

        let html = CGGMP_HTML
            .replace("${FILE_NAME}", &format!("{}.js", file_name));

        let mut js_file = output_dir.join(file_name);
        js_file.set_extension("js");

        let mut html_file = output_dir.join(file_name);
        html_file.set_extension("html");

        fs::write(js_file, js).expect("to write javascript");
        fs::write(html_file, html).expect("to write html");
    }
}
