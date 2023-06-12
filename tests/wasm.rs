#[cfg(all(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

    use futures::{select, stream::StreamExt, FutureExt};
    use mpc_relay_client::{
        ClientOptions, Event, WebClient, WebEventLoop,
    };
    use mpc_relay_protocol::{generate_keypair, hex, snow::Keypair};
    use tokio::sync::mpsc;

    const SERVER: &str = "ws://127.0.0.1:8008";
    const SERVER_PUBLIC_KEY: &str = "7fa066392ae34ca5aeca907ff100a7d9e37e5a851dcaa7c5e7c4fef946ee3a25";

    async fn new_client(
    ) -> Result<(WebClient, WebEventLoop, Keypair), JsValue> {
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
            WebClient::new(&url, options).await?;
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

        initiator.connect().await?;
        participant.connect().await?;

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let ev_i = peer_channel_initiator_client(
            init_client,
            event_loop_i,
            shutdown_tx,
        );
        let ev_p = peer_channel_participant_client(
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

    async fn peer_channel_initiator_client(
        mut client: WebClient,
        event_loop: WebEventLoop,
        shutdown_tx: mpsc::Sender<()>,
    ) -> Result<(), JsValue> {
        let mut s = event_loop.run();
        while let Some(event) = s.next().await {
            let event = event?;
            //log::info!("initiator {:#?}", event);
            match &event {
                // Once the peer connection is established we can
                // start sending messages over the encrypted channel
                Event::PeerConnected { peer_key } => {
                    // Send the ping
                    client.send(&peer_key, "ping", None).await?;
                }
                Event::JsonMessage { message, .. } => {
                    let message: &str = message.deserialize()?;
                    if message == "pong" {
                        // Got a pong so break out of the event loop
                        let _ = shutdown_tx.send(()).await;
                        break;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn peer_channel_participant_client(
        mut client: WebClient,
        event_loop: WebEventLoop,
        initiator_public_key: &[u8],
        mut shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<(), JsValue> {
        let mut s = event_loop.run();
        loop {
            select! {
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            //log::info!("participant {:#?}", event);
                            match &event {
                                Event::ServerConnected { .. } => {
                                    // Now we can connect to a peer
                                    client.connect_peer(initiator_public_key).await?;
                                }
                                // Once the peer connection is established
                                // we can start sending messages over
                                // the encrypted channel
                                Event::JsonMessage { peer_key, message, .. } => {
                                    let message: &str = message.deserialize()?;
                                    if message == "ping" {
                                        client.send(&peer_key, "pong", None).await?;
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                shutdown = shutdown_rx.recv().fuse() => {
                    if shutdown.is_some() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
