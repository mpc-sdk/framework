//! Distributed key generation.
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use super::KeygenOptions;

/// Initiate distributed key generation.
#[wasm_bindgen(js_name = "keygenInit")]
pub fn keygen_init(options: JsValue) -> Result<JsValue, JsError> {
    let options: KeygenOptions =
        serde_wasm_bindgen::from_value(options)?;
    Ok(future_to_promise(run_keygen_init(options)).into())
}

async fn run_keygen_init(
    options: KeygenOptions,
) -> Result<JsValue, JsValue> {
    todo!();
}
