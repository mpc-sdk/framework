//! Bindings for the CGGMP protocol.
use mpc_driver::synedrion::{
    ecdsa::{SigningKey, VerifyingKey},
    SessionId,
};
use mpc_driver::{
    Participant, PartyOptions, PrivateKey, SessionOptions,
};
use mpc_protocol::{hex, PATTERN};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// CGGMP protocol.
#[napi]
pub struct CggmpProtocol;

#[napi]
impl CggmpProtocol {
    /// Create a CGGMP protocol.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self
    }

    /// Distributed key generation.
    #[napi]
    pub async fn keygen(
        &self,
        options: JsUnknown,
        party: JsUnknown,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
    ) -> Result<JsUnknown> {
        let options: SessionOptions = napi::serde::from_unknown(options)?;
        let party: PartyOptions = napi::serde::from_unknown(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::from)?;
        let participant =
            Participant::new(signer, party).map_err(Error::from)?;
        let key_share = mpc_driver::keygen(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
        )
        .await?;
        napi::serde::to_unknown(&key_share)
    }

    /// Sign a message.
    #[napi]
    pub async fn sign(
        &self,
        options: JsUnknown,
        party: JsUnknown,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        private_key: JsUnknown,
        message: JsUnknown,
    ) -> Result<JsUnknown> {
        let options: SessionOptions = napi::serde::from_unknown(options)?;
        let party: PartyOptions = napi::serde::from_unknown(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::from)?;
        let private_key: PrivateKey = napi::serde::from_unknown(private_key)?;
        let participant =
            Participant::new(signer, party).map_err(Error::from)?;

        let message = parse_message(message)?;
        let signature = mpc_driver::sign(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
            &private_key,
            &message,
        )
        .await?;
        napi::serde::to_unknown(&signature)
    }

    /// Reshare key shares.
    #[napi]
    pub async fn reshare(
        &self,
        options: JsUnknown,
        party: JsUnknown,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        account_verifying_key: JsUnknown,
        private_key: JsUnknown,
        old_threshold: i64,
        new_threshold: i64,
    ) -> Result<JsUnknown> {
        let options: SessionOptions = napi::serde::from_unknown(options)?;
        let party: PartyOptions = napi::serde::from_unknown(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::from)?;
        let account_verifying_key: VerifyingKey = napi::serde::from_unknown(account_verifying_key)?;
        let private_key: Option<PrivateKey> = napi::serde::from_unknown(private_key)?;
        let participant =
            Participant::new(signer, party).map_err(Error::from)?;

        let key_share = mpc_driver::reshare(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
            account_verifying_key,
            private_key.as_ref(),
            old_threshold as usize,
            new_threshold as usize,
        )
        .await?;
        napi::serde::to_unknown(&key_share)
    }

    /// Generate a BIP32 derived child key.
    #[napi(js_name = "deriveBip32")]
    pub fn derive_bip32(
        &self,
        private_key: JsUnknown,
        derivation_path: String,
    ) -> Result<JsUnknown> {
        use mpc_driver::bip32::DerivationPath;

        let private_key: PrivateKey = napi::serde::from_unknown(private_key)?;
        let derivation_path: DerivationPath =
            derivation_path.parse().map_err(Error::from)?;
        let child_key =
            mpc_driver::derive_bip32(&private_key, &derivation_path)?;

        napi::serde::to_unknown(&child_key)
    }
}

/// Generate a PEM-encoded keypair.
///
/// Uses the default noise protocol parameters
/// if no pattern is given.
#[napi(js_name = "generateKeypair")]
pub fn generate_keypair(
    pattern: Option<String>,
) -> Result<JsUnknown> {
    let pattern = pattern.unwrap_or_else(|| PATTERN.to_owned());
    let keypair = mpc_protocol::Keypair::new(pattern.parse().map_err(Error::from)?)?;
    let public_key = hex::encode(keypair.public_key());
    let pem = mpc_protocol::encode_keypair(&keypair);
    napi::serde::to_unknown(&(pem, public_key))
}

fn parse_message(message: JsUnknown) -> Result<[u8; 32]> {
    let message: String = napi::serde::from_unknown(message)?;
    let message: Vec<u8> =
        hex::decode(&message).map_err(Error::from)?;
    message.as_slice().try_into().map_err(Error::from)
}
