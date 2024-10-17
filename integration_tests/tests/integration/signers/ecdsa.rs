use anyhow::Result;
use mpc_driver::signers::ecdsa::EcdsaSigner;
use serde::Deserialize;
use std::borrow::Cow;

/// Test vectors are generated using `ethers`,
/// see scripts/ecdsa-test-vectors.
const TEST_VECTORS: &str = r#"
{
  "signedMessage": {
    "privateKey": "f64abc91d673bcf100c3cf2bc42507df566d36a18189ae41c377c55ee26a44fd",
    "message": "example message",
    "signature": {
      "r": "e75ae7a14cc57c75f1fcf7343c06f9e31419ccd06b25a788a0d596119bc187f2",
      "s": "75a1de718def771b819d352ffb3f2a95b41da3ecdcbc592b07f956c7828d210f",
      "v": 28
    }
  }
}
"#;

#[derive(Deserialize)]
struct EthereumSignature {
    #[serde(with = "hex::serde")]
    pub r: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub s: Vec<u8>,
    pub v: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestSignedMessage {
    #[serde(with = "hex::serde")]
    private_key: Vec<u8>,
    message: String,
    signature: EthereumSignature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVectors {
    signed_message: TestSignedMessage,
}

#[test]
fn integration_ecdsa_sign_message() -> Result<()> {
    let vectors: TestVectors = serde_json::from_str(TEST_VECTORS)?;
    let spec = vectors.signed_message;

    let signing_key =
        EcdsaSigner::from_slice(spec.private_key.as_slice())?;
    let signer = EcdsaSigner::new(Cow::Owned(signing_key));

    let (signature, recid) = signer.sign_eth_message(spec.message)?;
    let (r, s) = signature.split_bytes();

    assert_eq!(&spec.signature.r, r.as_slice());
    assert_eq!(&spec.signature.s, s.as_slice());
    assert_eq!(spec.signature.v - 27, u8::from(recid));

    /*
    println!("r: {:#?}", hex::encode(r));
    println!("s: {:#?}", hex::encode(s));
    println!("v: {:#?}", recid);
    */

    Ok(())
}
