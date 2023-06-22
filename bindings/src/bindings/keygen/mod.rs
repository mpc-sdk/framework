//! Distributed key generation.
use crate::{parse_participants, Protocol, SessionOptions};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

mod gg20;

/// Distributed key generation.
#[wasm_bindgen]
pub fn keygen(
    options: JsValue,
    participants: JsValue,
) -> Result<JsValue, JsError> {
    let options: SessionOptions =
        serde_wasm_bindgen::from_value(options)?;
    let participants = parse_participants(participants)?;
    match &options.protocol {
        Protocol::GG20 => {
            Ok(future_to_promise(gg20::keygen(options, participants))
                .into())
        }
        _ => todo!("drive CGGMP protocol"),
    }
}
