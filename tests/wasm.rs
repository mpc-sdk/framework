mod integration;

#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use super::integration::test_utils::{
        gg20, peer_channel, session_broadcast, session_handshake,
        session_timeout, socket_close,
    };
    use mpc_relay_protocol::hex;

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str =
        include_str!("./server_public_key.txt");
    
    /*
    /// Creates two clients that handshake with the server
    /// and then each other. Once the peer handshakes are
    /// complete they send "ping" and "pong" messages over
    /// the noise transport channel.
    #[wasm_bindgen_test]
    async fn peer_channel() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY.trim()).unwrap();
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
            hex::decode(SERVER_PUBLIC_KEY.trim()).unwrap();

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

    /// Uses the session helpers from the driver library to determine
    /// when both participants in a session are active.
    #[wasm_bindgen_test]
    async fn session_handshake() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY.trim()).unwrap();

        let expected_participants = 2;
        let connected_participants =
            session_handshake::run(SERVER, server_public_key)
                .await
                .unwrap();
        assert_eq!(expected_participants, connected_participants);
        Ok(())
    }
    */

    /// GG20 keygen and signing.
    #[wasm_bindgen_test]
    async fn gg20() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY.trim()).unwrap();
        gg20::run(SERVER, server_public_key).await.unwrap();
        Ok(())
    }
    
    /*
    /// Creates two clients that handshake with the server.
    ///
    /// The first client creates a session but the second
    /// client never joins the session so we get a timeout event.
    #[wasm_bindgen_test]
    async fn session_timeout() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY.trim()).unwrap();
        session_timeout::run(SERVER, server_public_key)
            .await
            .unwrap();
        Ok(())
    }

    /// Creates a client that handshakes with the server and
    /// then explicitly closes the connection.
    #[wasm_bindgen_test]
    async fn socket_close() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY.trim()).unwrap();
        socket_close::run(SERVER, server_public_key).await.unwrap();
        Ok(())
    }
    */
}
