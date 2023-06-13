mod integration;

#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use mpc_relay_protocol::hex;
    use tokio::sync::mpsc;

    use super::integration::test_utils::{new_client, peer_channel};

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str = "7fa066392ae34ca5aeca907ff100a7d9e37e5a851dcaa7c5e7c4fef946ee3a25";

    #[wasm_bindgen_test]
    async fn peer_channel() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());

        let server_public_key = hex::decode(SERVER_PUBLIC_KEY).unwrap();

        let (initiator, event_loop_i, initiator_key) =
            new_client::<JsValue>(
                SERVER,
                server_public_key.clone(),
            )
            .await?;
        let (participant, event_loop_p, _participant_key) =
            new_client::<JsValue>(
                SERVER,
                server_public_key.clone(),
            )
            .await?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        let ev_i = peer_channel::initiator_client::<JsValue>(
            initiator,
            event_loop_i,
            shutdown_tx,
        );
        let ev_p = peer_channel::participant_client::<JsValue>(
            participant,
            event_loop_p,
            &initiator_key.public,
            shutdown_rx,
        );

        // Must drive the event loop futures
        let (res_i, res_p) = futures::join!(ev_i, ev_p);

        assert!(res_i.is_ok());
        assert!(res_p.is_ok());

        Ok(())
    }
}
