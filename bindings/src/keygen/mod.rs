//! Distributed key generation.
use crate::{KeygenOptions, Protocol};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

mod gg20;

/// Initiate distributed key generation.
#[wasm_bindgen(js_name = "keygenInit")]
pub fn keygen_init(
    options: JsValue,
    participants: JsValue,
) -> Result<JsValue, JsError> {
    let options: KeygenOptions =
        serde_wasm_bindgen::from_value(options)?;
    let participants: Vec<Vec<u8>> =
        serde_wasm_bindgen::from_value(participants)?;

    match &options.protocol {
        Protocol::GG20 => Ok(future_to_promise(gg20::keygen_init(
            options,
            participants,
        ))
        .into()),
        _ => todo!("drive CGGMP protocol"),
    }
}

/// Join distributed key generation.
#[wasm_bindgen(js_name = "keygenJoin")]
pub fn keygen_join(
    options: JsValue,
) -> Result<JsValue, JsError> {
    let options: KeygenOptions =
        serde_wasm_bindgen::from_value(options)?;
    match &options.protocol {
        Protocol::GG20 => Ok(future_to_promise(gg20::keygen_join(
            options,
        ))
        .into()),
        _ => todo!("drive CGGMP protocol"),
    }
}
