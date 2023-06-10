use anyhow::Result;
use futures::{select, Future, FutureExt, StreamExt};
use mpc_relay_client::{Error, Event, EventLoop, NativeClient};
use serial_test::serial;
use std::pin::Pin;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
};

use crate::test_utils::{new_client, spawn_server};

/// Creates three clients that handshake with the server
/// and then each other.
///
/// Once the handshakes are complete a session is created
/// and the initiator broadcasts a message to all participants.
#[tokio::test]
#[serial]
async fn integration_session_broadcast() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    // Create new clients
    let (mut initiator, mut event_loop_i, _) = new_client().await?;
    let (mut participant_1, mut event_loop_p_1, participant_key_1) =
        new_client().await?;
    let (mut participant_2, mut event_loop_p_2, participant_key_2) =
        new_client().await?;

    // Copy clients to move into the event loops
    let mut init_client = initiator.clone();
    let mut part_1_client = participant_1.clone();
    let mut part_2_client = participant_2.clone();

    let session_participants = vec![
        participant_key_1.public.clone(),
        participant_key_2.public.clone(),
    ];

    // Notification channel for when all the clients are
    // connected to the server.
    let (server_conn_tx, server_conn_rx) = mpsc::channel::<()>(16);
    let (shutdown_tx, _) = broadcast::channel::<()>(16);

    // Setup event loops
    let shutdown_init_tx = shutdown_tx.clone();

    let ev_i = event_loop_1(
        event_loop_i,
        init_client,
        session_participants,
        server_conn_rx,
    );
    let ev_p_1 = event_loop_2(event_loop_p_1, part_1_client);
    let ev_p_2 = event_loop_3(event_loop_p_2, part_2_client);

    // Clients must handshake with the server first
    initiator.connect().await?;
    participant_1.connect().await?;
    participant_2.connect().await?;

    // Inform the initiator that all clients
    // are connected to the server
    server_conn_tx.send(()).await?;

    // Must drive the event loop futures
    let (res_i, res_p_1, res_p_2) =
        futures::join!(ev_i, ev_p_1, ev_p_2);

    println!("{:#?}", res_i);

    assert!(res_i?.is_ok());
    assert!(res_p_1?.is_ok());
    assert!(res_p_2?.is_ok());

    Ok(())
}

fn event_loop_1(
    mut event_loop: EventLoop,
    mut client: NativeClient,
    session_participants: Vec<Vec<u8>>,
    mut server_conn_rx: mpsc::Receiver<()>,
) -> JoinHandle<Result<()>> {
    async fn handler(
        client: &mut NativeClient,
        event: Event,
    ) -> Result<()> {
        match &event {
            Event::SessionReady(session) => {
                println!(
                    "part 1 got session ready {}",
                    session.session_id
                );

                for key in &session.all_participants {
                    if key != client.public_key() {
                        println!("connect peers");
                        let _ = client.try_connect_peer(key).await?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    tokio::task::spawn(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                _ = server_conn_rx.recv().fuse() => {
                    // Initiate a session context for broadcasting
                    client
                        .new_session(session_participants.clone())
                        .await?;
                }
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            handler(&mut client, event).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn event_loop_2(
    mut event_loop: EventLoop,
    mut client: NativeClient,
) -> JoinHandle<Result<()>> {
    async fn handler(
        client: &mut NativeClient,
        event: Event,
    ) -> Result<()> {
        match &event {
            Event::SessionReady(session) => {
                println!(
                    "part 1 got session ready {}",
                    session.session_id
                );

                for key in &session.all_participants {
                    if key != client.public_key() {
                        println!("connect peers");
                        let _ = client.try_connect_peer(key).await?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    tokio::task::spawn(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                /*
                _ = server_conn_rx.recv().fuse() => {
                    // Initiate a session context for broadcasting
                    init_client
                        .new_session(session_participants.clone())
                        .await?;
                }
                */
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            handler(&mut client, event).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn event_loop_3(
    mut event_loop: EventLoop,
    mut client: NativeClient,
) -> JoinHandle<Result<()>> {
    async fn handler(
        client: &mut NativeClient,
        event: Event,
    ) -> Result<()> {
        match &event {
            Event::SessionReady(session) => {
                println!(
                    "part 1 got session ready {}",
                    session.session_id
                );

                for key in &session.all_participants {
                    if key != client.public_key() {
                        println!("connect peers");
                        let _ = client.try_connect_peer(key).await?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    tokio::task::spawn(async move {
        let mut s = event_loop.run();
        loop {
            select! {
                /*
                _ = server_conn_rx.recv().fuse() => {
                    // Initiate a session context for broadcasting
                    init_client
                        .new_session(session_participants.clone())
                        .await?;
                }
                */
                event = s.next().fuse() => {
                    match event {
                        Some(event) => {
                            let event = event?;
                            handler(&mut client, event).await?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}
