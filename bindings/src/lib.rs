//! Webassembly bindings for the web platform.
#![deny(missing_docs)]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod bindings {
    use mpc_protocol::hex;
    use wasm_bindgen::prelude::*;

    /// Initialize the panic hook and logging.
    #[doc(hidden)]
    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
        if wasm_log::try_init(wasm_log::Config::new(log::Level::Debug))
            .is_ok()
        {
            log::info!("Webassembly logger initialized");
        }
    }

    use mpc_driver::{PrivateKey, SessionOptions};
    use wasm_bindgen_futures::future_to_promise;

    /// Distributed key generation.
    #[wasm_bindgen]
    pub fn keygen(
        options: JsValue,
        participants: JsValue,
    ) -> Result<JsValue, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let participants = parse_participants(participants)?;

        let fut = async move {
            let key_share = mpc_driver::keygen(options, participants).await?;
            Ok(serde_wasm_bindgen::to_value(&key_share)?)
        };

        Ok(future_to_promise(fut).into())
    }

    /// Sign a message.
    #[wasm_bindgen]
    pub fn sign(
        options: JsValue,
        participants: JsValue,
        signing_key: JsValue,
        message: JsValue,
    ) -> Result<JsValue, JsError> {
        let options: SessionOptions =
            serde_wasm_bindgen::from_value(options)?;
        let participants = parse_participants(participants)?;
        let signing_key: PrivateKey =
            serde_wasm_bindgen::from_value(signing_key)?;
        let message = parse_message(message)?;

        let fut = async move {
            let signature = mpc_driver::sign(
                options,
                participants,
                signing_key,
                message,
            ).await?;
            Ok(serde_wasm_bindgen::to_value(&signature)?)
        };

        Ok(future_to_promise(fut).into())
    }

    pub(crate) fn parse_participants(
        participants: JsValue,
    ) -> Result<Option<Vec<Vec<u8>>>, JsError> {
        let participants: Option<Vec<String>> =
            serde_wasm_bindgen::from_value(participants)?;
        if let Some(participants) = participants {
            let mut parties = Vec::new();
            for participant in participants {
                parties.push(
                    hex::decode(participant).map_err(JsError::from)?,
                );
            }
            Ok(Some(parties))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn parse_message(
        message: JsValue,
    ) -> Result<[u8; 32], JsError> {
        let message: String = serde_wasm_bindgen::from_value(message)?;
        let message: Vec<u8> =
            hex::decode(&message).map_err(JsError::from)?;
        let message: [u8; 32] =
            message.as_slice().try_into().map_err(JsError::from)?;
        Ok(message)
    }
}
