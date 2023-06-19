//! Webassembly bindings for the web platform.
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
mod sign;
mod types;

pub use types::*;

use mpc_protocol::Keypair;
use mpc_client::{Client, ClientOptions, EventLoop};

/// Create a new relay client using the provided keypair connected
/// to a relay server.
pub async fn new_client_with_keypair(
    server: &str,
    server_public_key: Vec<u8>,
    keypair: Keypair,
) -> Result<(Client, EventLoop), JsValue> {
    let options = ClientOptions {
        keypair,
        server_public_key,
    };
    let url = options.url(server);
    Ok(Client::new(&url, options).await?)
}
