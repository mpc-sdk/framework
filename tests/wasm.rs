mod integration;

#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use futures::{select, stream::StreamExt, FutureExt};
    use mpc_relay_client::{
        ClientOptions, Event, Client, EventLoop,
    };
    use mpc_relay_protocol::{generate_keypair, hex, snow::Keypair};
    use tokio::sync::mpsc;

    use super::integration::test_utils::peer_channel;

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str = "7fa066392ae34ca5aeca907ff100a7d9e37e5a851dcaa7c5e7c4fef946ee3a25";

    async fn new_client(
    ) -> Result<(Client, EventLoop, Keypair), JsValue> {
        let keypair = generate_keypair().unwrap();
        let server_public_key =
            hex::decode(SERVER_PUBLIC_KEY).unwrap();
        let copy = Keypair {
            public: keypair.public.clone(),
            private: keypair.public.clone(),
        };
        let options = ClientOptions {
            server_public_key,
            keypair,
        };
        let url = options.url(SERVER);
        let (client, event_loop) =
            Client::new(&url, options).await?;
        Ok((client, event_loop, copy))
    }

    #[wasm_bindgen_test]
    async fn peer_channel() -> Result<(), JsValue> {
        let _ = wasm_log::try_init(wasm_log::Config::default());

        let (mut initiator, event_loop_i, initiator_key) =
            new_client().await?;
        let (mut participant, event_loop_p, participant_key) =
            new_client().await?;

        // Copy clients to move into the event loops
        let init_client = initiator.clone();
        let part_client = participant.clone();

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let ev_i = peer_channel::initiator_client::<JsValue>(
            init_client,
            event_loop_i,
            shutdown_tx,
        );
        let ev_p = peer_channel::participant_client::<JsValue>(
            part_client,
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
