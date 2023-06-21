//! Distributed key generation.
use crate::PrivateKey;
use crate::{parse_participants, parse_message, Protocol, SessionOptions};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

mod gg20;

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
    match &options.protocol {
        Protocol::GG20 => {
            assert!(matches!(signing_key, PrivateKey::GG20(_)));
            Ok(future_to_promise(gg20::sign(
                options,
                signing_key,
                message,
                participants,
            ))
            .into())
        }
        _ => todo!("drive CGGMP protocol"),
    }
}
