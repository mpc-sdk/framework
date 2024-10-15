//! Webassembly bindings for the web platform.
#![deny(missing_docs)]

#[cfg(all(
    feature = "ecdsa",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod ecdsa;

#[cfg(all(
    feature = "eddsa",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod eddsa;

#[cfg(all(
    feature = "schnorr",
    target_arch = "wasm32",
    target_os = "unknown"
))]
pub mod schnorr;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod bindings {
    use mpc_driver::synedrion::{
        ecdsa::{SigningKey, VerifyingKey},
        SessionId,
    };
    use mpc_driver::{
        meeting, MeetingOptions, Participant, PartyOptions,
        PrivateKey, SessionOptions,
    };
    use mpc_protocol::{hex, MeetingId, UserId, PATTERN};
    use serde_json::Value;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::future_to_promise;

    /// Initialize the panic hook and logging.
    #[doc(hidden)]
    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();

        #[cfg(feature = "tracing")]
        {
            use tracing_subscriber::fmt;
            use tracing_subscriber_wasm::MakeConsoleWriter;
            fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(
                    MakeConsoleWriter::default()
                        .map_trace_level_to(tracing::Level::DEBUG),
                )
                // For some reason, if we don't do this
                // in the browser, we get
                // a runtime error.
                .without_time()
                .init();

            log::info!("Webassembly tracing initialized");
        }
    }

    /// Distributed key generation.
    #[wasm_bindgen(js_name = "keygen")]
    pub fn keygen_cggmp(
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
    #[wasm_bindgen(js_name = "sign")]
    pub fn sign_cggmp(
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
    #[wasm_bindgen(js_name = "reshare")]
    pub fn reshare_cggmp(
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
        let message: String =
            serde_wasm_bindgen::from_value(message)?;
        let message: Vec<u8> =
            hex::decode(&message).map_err(JsError::from)?;
        let message: [u8; 32] =
            message.as_slice().try_into().map_err(JsError::from)?;
        Ok(message)
    }

    /// Create a meeting point used to exchange public keys.
    #[wasm_bindgen(js_name = "createMeeting")]
    pub fn create_meeting(
        options: JsValue,
        identifiers: JsValue,
        initiator: String,
        data: JsValue,
    ) -> Result<JsValue, JsError> {
        let options: MeetingOptions =
            serde_wasm_bindgen::from_value(options)?;
        let identifiers = parse_user_identifiers(identifiers)?;
        let initiator = parse_user_id(initiator)?;
        let data: Value = serde_wasm_bindgen::from_value(data)?;
        let fut = async move {
            let meeting_id = meeting::create(
                options,
                identifiers,
                initiator,
                data,
            )
            .await?;
            Ok(serde_wasm_bindgen::to_value(&meeting_id)?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Join a meeting point used to exchange public keys.
    #[wasm_bindgen(js_name = "joinMeeting")]
    pub fn join_meeting(
        options: JsValue,
        meeting_id: String,
        user_id: JsValue,
    ) -> Result<JsValue, JsError> {
        let options: MeetingOptions =
            serde_wasm_bindgen::from_value(options)?;
        let meeting_id: MeetingId =
            meeting_id.parse().map_err(JsError::from)?;
        let user_id: Option<String> =
            serde_wasm_bindgen::from_value(user_id)?;
        let user_id = if let Some(user_id) = user_id {
            Some(parse_user_id(user_id)?)
        } else {
            None
        };

        let fut = async move {
            let (public_keys, data) =
                meeting::join(options, meeting_id, user_id).await?;
            let public_keys: Vec<String> = public_keys
                .into_iter()
                .map(|v| hex::encode(v))
                .collect();
            Ok(serde_wasm_bindgen::to_value(&(public_keys, data))?)
        };
        Ok(future_to_promise(fut).into())
    }

    /// Parse a collection of user identifiers.
    fn parse_user_identifiers(
        identifiers: JsValue,
    ) -> Result<Vec<UserId>, JsError> {
        let identifiers: Vec<String> =
            serde_wasm_bindgen::from_value(identifiers)?;
        let mut ids = Vec::new();
        for id in identifiers {
            ids.push(parse_user_id(id)?);
        }
        Ok(ids)
    }

    /// Parse a single hex-encoded user identifier (SHA256 checksum).
    fn parse_user_id(id: String) -> Result<UserId, JsError> {
        let id = hex::decode(id).map_err(JsError::from)?;
        let id: [u8; 32] =
            id.as_slice().try_into().map_err(JsError::from)?;
        Ok(id.into())
    }
}
