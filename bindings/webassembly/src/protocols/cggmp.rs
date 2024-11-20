//! Bindings for the CGGMP protocol.
use mpc_driver::synedrion::{
    self,
    ecdsa::{SigningKey, VerifyingKey},
    SessionId,
};
use mpc_driver::{
    cggmp::{Participant, PartyOptions},
    SessionOptions,
};
use mpc_protocol::{hex, PATTERN};
use std::collections::BTreeSet;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

#[cfg(not(debug_assertions))]
type Params = synedrion::ProductionParams;
#[cfg(debug_assertions)]
type Params = synedrion::TestParams;

type KeyShare = synedrion::ThresholdKeyShare<Params, VerifyingKey>;

/// CGGMP protocol.
#[wasm_bindgen]
pub struct CggmpProtocol {
    options: SessionOptions,
    key_share: KeyShare,
}

#[wasm_bindgen]
impl CggmpProtocol {
    /// Create a CGGMP protocol.
    #[wasm_bindgen(constructor)]
    pub fn new(
        options: JsValue,
        key_share: JsValue,
    ) -> Result<CggmpProtocol, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let key_share: KeyShare =
            serde_wasm_bindgen::from_value(key_share)?;
        Ok(Self { options, key_share })
    }

    /// Verifying key for this signer.
    #[wasm_bindgen(js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.key_share.verifying_key().to_sec1_bytes().to_vec()
    }

    /// Compute the Ethereum address for the verifying key.
    pub fn address(&self) -> String {
        let public_key = self
            .key_share
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        mpc_driver::address(&public_key)
    }

    /// Distributed key generation.
    pub fn keygen(
        options: JsValue,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
    ) -> Result<JsValue, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let verifier = signer.verifying_key().clone();
        let participant = Participant::new(signer, verifier, party)
            .map_err(JsError::from)?;
        let fut = async move {
            let key_share = mpc_client::cggmp::keygen::<Params>(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
            )
            .await?;

            Ok(serde_wasm_bindgen::to_value(&key_share)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Sign a message.
    pub fn sign(
        &self,
        // options: JsValue,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        // key_share: JsValue,
        message: String,
    ) -> Result<JsValue, JsError> {
        let options = self.options.clone();
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let verifier = signer.verifying_key().clone();
        let participant = Participant::new(signer, verifier, party)
            .map_err(JsError::from)?;

        let mut selected_parties = BTreeSet::new();
        selected_parties
            .extend(participant.party().verifiers().iter());
        let key_share =
            self.key_share.to_key_share(&selected_parties);

        let message: Vec<u8> =
            hex::decode(&message).map_err(JsError::from)?;
        let message: [u8; 32] =
            message.as_slice().try_into().map_err(JsError::from)?;

        let fut = async move {
            let signature = mpc_client::cggmp::sign(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
                &key_share,
                &message,
            )
            .await?;
            Ok(serde_wasm_bindgen::to_value(&signature)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Reshare key shares.
    pub fn reshare(
        &self,
        // options: JsValue,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        account_verifying_key: JsValue,
        key_share: JsValue,
        old_threshold: usize,
        new_threshold: usize,
    ) -> Result<JsValue, JsError> {
        let options = self.options.clone();
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let verifier = signer.verifying_key().clone();
        let account_verifying_key: VerifyingKey =
            serde_wasm_bindgen::from_value(account_verifying_key)?;
        let key_share: Option<KeyShare> =
            serde_wasm_bindgen::from_value(key_share)?;
        let participant = Participant::new(signer, verifier, party)
            .map_err(JsError::from)?;

        let fut = async move {
            let key_share = mpc_client::cggmp::reshare(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
                account_verifying_key,
                key_share,
                old_threshold,
                new_threshold,
            )
            .await?;
            Ok(serde_wasm_bindgen::to_value(&key_share)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Generate a BIP32 derived child key.
    #[wasm_bindgen(js_name = "deriveBip32")]
    pub fn derive_bip32(
        &self,
        derivation_path: String,
    ) -> Result<JsValue, JsError> {
        use mpc_driver::bip32::DerivationPath;

        let derivation_path: DerivationPath =
            derivation_path.parse()?;
        let child_key = mpc_driver::cggmp::derive_bip32(
            &self.key_share,
            &derivation_path,
        )?;

        Ok(serde_wasm_bindgen::to_value(&child_key)?)
    }

    /// Generate a PEM-encoded keypair for the noise protocol.
    ///
    /// Uses the default noise protocol parameters
    /// if no pattern is given.
    #[wasm_bindgen(js_name = "generateKeypair")]
    pub fn generate_keypair(
        pattern: Option<String>,
    ) -> Result<JsValue, JsError> {
        let pattern = if let Some(pattern) = pattern {
            pattern
        } else {
            PATTERN.to_owned()
        };
        let keypair = mpc_protocol::Keypair::new(pattern.parse()?)?;
        let public_key = hex::encode(keypair.public_key());
        let pem = mpc_protocol::encode_keypair(&keypair);
        Ok(serde_wasm_bindgen::to_value(&(pem, public_key))?)
    }
}
