//! Bindings for the CGGMP protocol.
use mpc_driver::synedrion::{
    ecdsa::{SigningKey, VerifyingKey},
    SessionId,
};
use mpc_driver::{
    Participant, PartyOptions, PrivateKey, SessionOptions,
};
use mpc_protocol::{hex, PATTERN};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// CGGMP protocol.
#[wasm_bindgen]
pub struct CggmpProtocol;

#[wasm_bindgen]
impl CggmpProtocol {
    /// Create a CGGMP protocol.
    #[wasm_bindgen(constructor)]
    pub fn new() -> CggmpProtocol {
        Self
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
        let participant =
            Participant::new(signer, party).map_err(JsError::from)?;
        let fut = async move {
            let key_share = mpc_driver::keygen(
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
        options: JsValue,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        private_key: JsValue,
        message: JsValue,
    ) -> Result<JsValue, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let private_key: PrivateKey =
            serde_wasm_bindgen::from_value(private_key)?;
        let participant =
            Participant::new(signer, party).map_err(JsError::from)?;

        let message = parse_message(message)?;
        let fut = async move {
            let signature = mpc_driver::sign(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
                &private_key,
                &message,
            )
            .await?;
            Ok(serde_wasm_bindgen::to_value(&signature)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Reshare key shares.
    pub fn reshare(
        options: JsValue,
        party: JsValue,
        session_id_seed: Vec<u8>,
        signer: Vec<u8>,
        account_verifying_key: JsValue,
        private_key: JsValue,
        old_threshold: usize,
        new_threshold: usize,
    ) -> Result<JsValue, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let party: PartyOptions =
            serde_wasm_bindgen::from_value(party)?;
        let signer: SigningKey =
            signer.as_slice().try_into().map_err(JsError::from)?;
        let account_verifying_key: VerifyingKey =
            serde_wasm_bindgen::from_value(account_verifying_key)?;
        let private_key: Option<PrivateKey> =
            serde_wasm_bindgen::from_value(private_key)?;
        let participant =
            Participant::new(signer, party).map_err(JsError::from)?;

        let fut = async move {
            let key_share = mpc_driver::reshare(
                options,
                participant,
                SessionId::from_seed(&session_id_seed),
                account_verifying_key,
                private_key.as_ref(),
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
        private_key: JsValue,
        derivation_path: String,
    ) -> Result<JsValue, JsError> {
        use mpc_driver::bip32::DerivationPath;

        let private_key: PrivateKey =
            serde_wasm_bindgen::from_value(private_key)?;
        let derivation_path: DerivationPath =
            derivation_path.parse()?;
        let child_key =
            mpc_driver::derive_bip32(&private_key, &derivation_path)?;

        Ok(serde_wasm_bindgen::to_value(&child_key)?)
    }
}

/// Generate a PEM-encoded keypair.
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

fn parse_message(message: JsValue) -> Result<[u8; 32], JsError> {
    let message: String = serde_wasm_bindgen::from_value(message)?;
    let message: Vec<u8> =
        hex::decode(&message).map_err(JsError::from)?;
    let message: [u8; 32] =
        message.as_slice().try_into().map_err(JsError::from)?;
    Ok(message)
}
