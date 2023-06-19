//! Webassembly bindings for the web platform.
#![deny(missing_docs)]
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

mod keygen;
mod types;

pub use types::*;
