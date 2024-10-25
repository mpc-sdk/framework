use mpc_driver::synedrion::ecdsa;
use mpc_protocol::hex;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyingKey {
    pub bytes: Vec<u8>,
}

impl TryFrom<VerifyingKey> for ecdsa::VerifyingKey {
    type Error = mpc_driver::Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Ok(ecdsa::VerifyingKey::from_sec1_bytes(&value.bytes)?)
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair {
    pub pem: String,
}

impl TryFrom<Keypair> for mpc_protocol::Keypair {
    type Error = mpc_driver::Error;

    fn try_from(value: Keypair) -> Result<Self, Self::Error> {
        todo!();
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Parameters {
    pub parties: u16,
    pub threshold: u16,
}

impl From<Parameters> for mpc_protocol::Parameters {
    fn from(value: Parameters) -> Self {
        mpc_protocol::Parameters {
            parties: value.parties,
            threshold: value.threshold,
        }
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOptions {
    pub server_url: String,
    #[serde(with = "hex::serde")]
    pub server_public_key: Vec<u8>,
    pub pattern: Option<String>,
}

impl From<ServerOptions> for mpc_driver::ServerOptions {
    fn from(value: ServerOptions) -> Self {
        mpc_driver::ServerOptions {
            server_url: value.server_url,
            server_public_key: value.server_public_key,
            pattern: value.pattern,
        }
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionOptions {
    pub keypair: Keypair,
    pub server: ServerOptions,
    pub parameters: Parameters,
}

impl TryFrom<SessionOptions> for mpc_driver::SessionOptions {
    type Error = mpc_driver::Error;

    fn try_from(value: SessionOptions) -> Result<Self, Self::Error> {
        Ok(mpc_driver::SessionOptions {
            keypair: value.keypair.try_into()?,
            server: value.server.into(),
            parameters: value.parameters.into(),
        })
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions {
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    pub participants: Vec<Vec<u8>>,
    pub is_initiator: bool,
    pub verifiers: Vec<VerifyingKey>,
}

impl TryFrom<PartyOptions> for mpc_driver::PartyOptions {
    type Error = mpc_driver::Error;

    fn try_from(value: PartyOptions) -> Result<Self, Self::Error> {
        let mut verifiers = Vec::with_capacity(value.verifiers.len());
        for verifier in value.verifiers {
            verifiers.push(verifier.try_into()?);
        }
        Ok(mpc_driver::PartyOptions::new(
            value.public_key,
            value.participants,
            value.is_initiator,
            verifiers,
        )?)
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyShare {
    pub index: u32,
}

impl From<KeyShare> for mpc_driver::KeyShare {
    fn from(value: KeyShare) -> Self {
        todo!();
    }
}

impl TryFrom<mpc_driver::KeyShare> for KeyShare {
    type Error = mpc_driver::Error;

    fn try_from(
        value: mpc_driver::KeyShare,
    ) -> Result<Self, Self::Error> {
        todo!();
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKey {
    pub index: u32,
}

impl From<PrivateKey> for mpc_driver::PrivateKey {
    fn from(value: PrivateKey) -> Self {
        todo!();
    }
}

impl TryFrom<mpc_driver::PrivateKey> for PrivateKey {
    type Error = mpc_driver::Error;

    fn try_from(
        value: mpc_driver::PrivateKey,
    ) -> Result<Self, Self::Error> {
        todo!();
    }
}

#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Signature {
    pub index: u32,
}

impl From<Signature> for mpc_driver::Signature {
    fn from(value: Signature) -> Self {
        todo!();
    }
}

impl TryFrom<mpc_driver::Signature> for Signature {
    type Error = mpc_driver::Error;

    fn try_from(
        value: mpc_driver::Signature,
    ) -> Result<Self, Self::Error> {
        todo!();
    }
}
