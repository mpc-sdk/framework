mod integration;

#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use super::integration::test_utils::{
        peer_channel, session_broadcast,
    };
    use mpc_relay_protocol::hex;

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str = "7fa066392ae34ca5aeca907ff100a7d9e37e5a851dcaa7c5e7c4fef946ee3a25";

    /// Creates two clients that handshake with the server
    /// and then each other. Once the peer handshakes are
    /// complete they send "ping" and "pong" messages over
    /// the noise transport channel.
    #[wasm_bindgen_test]
    async fn peer_channel() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY).unwrap();
        peer_channel::run(SERVER, server_public_key).await.unwrap();
        Ok(())
    }

    /// Creates three clients that handshake with the server
    /// and then each other.
    ///
    /// Once the handshakes are complete a session is created
    /// and each node broadcasts a message to all the other
    /// participants in the session.
    #[wasm_bindgen_test]
    async fn session_broadcast() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());

        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY).unwrap();

        let expected_result = vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8];
        let session_result =
            session_broadcast::run(SERVER, server_public_key)
                .await
                .unwrap();
        let mut result = session_result.lock().await;
        result.sort();
        assert_eq!(expected_result, result.clone());

        Ok(())
    }
}
