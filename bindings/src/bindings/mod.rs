//! Webassembly bindings for the web platform.
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

mod keygen;
mod sign;
mod types;

pub use types::*;

use mpc_client::{Client, ClientOptions, EventLoop};
use mpc_protocol::Keypair;

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
