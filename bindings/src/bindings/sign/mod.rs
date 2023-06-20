//! Distributed key generation.
use crate::PrivateKey;
use crate::{Protocol, SessionOptions, parse_participants};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

mod gg20;

/// Sign a message.
#[wasm_bindgen]
pub fn sign(
    options: JsValue,
    signing_key: JsValue,
    message: Vec<u8>,
    participants: JsValue,
) -> Result<JsValue, JsError> {
    let options: SessionOptions =
        serde_wasm_bindgen::from_value(options)?;
    let signing_key: PrivateKey =
        serde_wasm_bindgen::from_value(signing_key)?;
    let message: [u8; 32] =
        message.as_slice().try_into().map_err(JsError::from)?;
    let participants = parse_participants(participants)?;
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
