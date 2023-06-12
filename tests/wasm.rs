#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use mpc_relay_client::{ClientOptions, WebClient};
    use mpc_relay_protocol::{generate_keypair, hex};

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str = "7fa066392ae34ca5aeca907ff100a7d9e37e5a851dcaa7c5e7c4fef946ee3a25";

    #[wasm_bindgen_test]
    async fn websocket_connection() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());

        let keypair = generate_keypair().unwrap();
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY).unwrap();
        let public_key = hex::encode(&keypair.public);
        let options = ClientOptions {
            server_public_key,
            keypair,
        };
        let url = options.url(SERVER);
        let client = WebClient::new(&url, options).await?;
        Ok(())
    }
}
