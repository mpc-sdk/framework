mod integration;

#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use mpc_relay_protocol::hex;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    use super::integration::test_utils::{
        new_client, peer_channel, session_broadcast,
    };

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str = "7fa066392ae34ca5aeca907ff100a7d9e37e5a851dcaa7c5e7c4fef946ee3a25";

    #[wasm_bindgen_test]
    async fn peer_channel() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());

        log::info!("peer_channel running...");

        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY).unwrap();
        let (initiator, event_loop_i, initiator_key) =
            new_client::<JsValue>(SERVER, server_public_key.clone())
                .await?;
        let (participant, event_loop_p, _participant_key) =
            new_client::<JsValue>(SERVER, server_public_key.clone())
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

    #[wasm_bindgen_test]
    async fn session_broadcast() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());

        log::info!("session_broadcast running");

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        log::info!("session_broadcast created runtime...");

        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY).unwrap();

        // Create new clients
        let (initiator, event_loop_i, _) =
            new_client::<JsValue>(SERVER, server_public_key.clone())
                .await?;
        let (participant_1, event_loop_p_1, participant_key_1) =
            new_client::<JsValue>(SERVER, server_public_key.clone())
                .await?;
        let (participant_2, event_loop_p_2, participant_key_2) =
            new_client::<JsValue>(SERVER, server_public_key.clone())
                .await?;

        let session_participants = vec![
            participant_key_1.public.clone(),
            participant_key_2.public.clone(),
        ];

        let expected_result = vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8];
        let session_result = Arc::new(Mutex::new(vec![]));

        log::info!("session broadcast spawning task...");

        let ev_i = session_broadcast::client_1(
            event_loop_i,
            initiator,
            Arc::clone(&session_result),
            session_participants,
        )
        .await
        .unwrap();

        let ev_p_1 = session_broadcast::client_2(
            event_loop_p_1,
            participant_1,
            Arc::clone(&session_result),
        )
        .await
        .unwrap();
        let ev_p_2 = session_broadcast::client_3(
            event_loop_p_2,
            participant_2,
            Arc::clone(&session_result),
        )
        .await
        .unwrap();

        // Must drive the event loop futures
        let (res_i, res_p_1, res_p_2) =
            futures::join!(ev_i, ev_p_1, ev_p_2);

        assert!(res_i.is_ok());
        assert!(res_p_1.is_ok());
        assert!(res_p_2.is_ok());

        let mut result = session_result.lock().await;
        result.sort();
        assert_eq!(expected_result, result.clone());

        Ok(())
    }
}
