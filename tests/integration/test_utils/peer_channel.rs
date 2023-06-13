use futures::{select, FutureExt, StreamExt};
use tokio::sync::mpsc;
use mpc_relay_client::{
    Event, Client, EventLoop,
};
use std::error::Error;

pub async fn initiator_client<E: From<mpc_relay_client::Error>>(
    mut client: Client,
    event_loop: EventLoop,
    shutdown_tx: mpsc::Sender<()>,
) -> Result<(), E> {
    client.connect().await?;

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

pub async fn participant_client<E: From<mpc_relay_client::Error>>(
    mut client: Client,
    event_loop: EventLoop,
    initiator_public_key: &[u8],
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<(), E> {
    client.connect().await?;

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
