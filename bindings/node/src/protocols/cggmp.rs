//! Bindings for the CGGMP protocol.
use anyhow::Error;
use mpc_driver::synedrion::{
    ecdsa::{self, SigningKey},
    SessionId,
};
use mpc_driver::Participant;
use mpc_protocol::{hex, PATTERN};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use super::types::{
    KeyShare, PartyOptions, PrivateKey, SessionOptions, Signature,
    VerifyingKey,
};

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
        options: SessionOptions,
        party: PartyOptions,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
    ) -> Result<KeyShare> {
        let options: mpc_driver::SessionOptions =
            options.try_into().map_err(Error::new)?;
        let party: mpc_driver::PartyOptions =
            party.try_into().map_err(Error::new)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::from)?;
        let participant =
            Participant::new(signer, party).map_err(Error::from)?;
        let key_share = mpc_driver::cggmp::keygen(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
        )
        .await
        .map_err(Error::new)?;

        let key_share: mpc_driver::KeyShare = key_share.into();

        let key_share: KeyShare =
            key_share.try_into().map_err(Error::new)?;
        Ok(key_share)
    }

    /// Sign a message.
    #[napi]
    pub async fn sign(
        &self,
        options: SessionOptions,
        party: PartyOptions,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        private_key: PrivateKey,
        message: String,
    ) -> Result<Signature> {
        let options: mpc_driver::SessionOptions =
            options.try_into().map_err(Error::new)?;
        let party: mpc_driver::PartyOptions =
            party.try_into().map_err(Error::new)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::from)?;
        let private_key: mpc_driver::PrivateKey = private_key.into();
        let message = hex::decode(&message).map_err(Error::new)?;
        let message: [u8; 32] =
            message.as_slice().try_into().map_err(Error::new)?;
        let participant =
            Participant::new(signer, party).map_err(Error::from)?;

        let signature = mpc_driver::sign(
            options,
            participant,
            SessionId::from_seed(&session_id_seed),
            &private_key,
            &message,
        )
        .await
        .map_err(Error::new)?;

        let signature: Signature =
            signature.try_into().map_err(Error::new)?;
        Ok(signature)
    }

    /// Reshare key shares.
    #[napi]
    pub async fn reshare(
        &self,
        options: SessionOptions,
        party: PartyOptions,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        account_verifying_key: VerifyingKey,
        private_key: Option<PrivateKey>,
        old_threshold: i64,
        new_threshold: i64,
    ) -> Result<KeyShare> {
        let options: mpc_driver::SessionOptions =
            options.try_into().map_err(Error::new)?;
        let party: mpc_driver::PartyOptions =
            party.try_into().map_err(Error::new)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(Error::from)?;

        let account_verifying_key: ecdsa::VerifyingKey =
            account_verifying_key.try_into().map_err(Error::new)?;

        let private_key: Option<mpc_driver::PrivateKey> =
            private_key.map(|k| k.into());
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
        .await
        .map_err(Error::new)?;

        let key_share: KeyShare =
            key_share.try_into().map_err(Error::new)?;
        Ok(key_share)
    }

    /// Generate a BIP32 derived child key.
    #[napi(js_name = "deriveBip32")]
    pub fn derive_bip32(
        &self,
        private_key: PrivateKey,
        derivation_path: String,
        env: Env,
    ) -> std::result::Result<napi::JsUnknown, napi::JsError> {
        use mpc_driver::bip32::DerivationPath;
        let private_key: mpc_driver::PrivateKey = private_key.into();
        let derivation_path: DerivationPath =
            derivation_path.parse().map_err(Error::from)?;
        let child_key =
            mpc_driver::derive_bip32(&private_key, &derivation_path)
                .map_err(Error::new)?;
        Ok(env.to_js_value(&child_key).map_err(Error::new)?)
    }
}

/// Generate a PEM-encoded keypair for the noise protocol.
///
/// Uses the default noise protocol parameters
/// if no pattern is given.
#[napi(js_name = "generateKeypair")]
pub fn generate_keypair(
    pattern: Option<String>,
    env: Env,
) -> std::result::Result<napi::JsUnknown, JsError> {
    let pattern = pattern.unwrap_or_else(|| PATTERN.to_owned());
    let keypair = mpc_protocol::Keypair::new(
        pattern.parse().map_err(Error::new)?,
    )
    .map_err(Error::new)?;
    let public_key = hex::encode(keypair.public_key());
    let pem = mpc_protocol::encode_keypair(&keypair);
    Ok(env.to_js_value(&(pem, public_key)).map_err(Error::new)?)
}
