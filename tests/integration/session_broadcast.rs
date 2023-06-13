use anyhow::Result;
use serial_test::serial;
use std::sync::Arc;
use tokio::{
    sync::Mutex,
};

use crate::test_utils::{
    new_client, server_public_key, spawn_server, SERVER, session_broadcast,
};

/// Creates three clients that handshake with the server
/// and then each other.
///
/// Once the handshakes are complete a session is created
/// and each node broadcasts a message to all the other
/// participants in the session.
#[tokio::test]
#[serial]
async fn integration_session_broadcast() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn_server()?;
    let _ = rx.await?;

    let server_public_key = server_public_key().await?;

    // Create new clients
    let (initiator, event_loop_i, _) = new_client::<anyhow::Error>(
        SERVER,
        server_public_key.clone(),
    )
    .await?;
    let (participant_1, event_loop_p_1, participant_key_1) =
        new_client::<anyhow::Error>(
            SERVER,
            server_public_key.clone(),
        )
        .await?;
    let (participant_2, event_loop_p_2, participant_key_2) =
        new_client::<anyhow::Error>(
            SERVER,
            server_public_key.clone(),
        )
        .await?;

    let session_participants = vec![
        participant_key_1.public.clone(),
        participant_key_2.public.clone(),
    ];

    let expected_result = vec![1u8, 1u8, 2u8, 2u8, 3u8, 3u8];
    let session_result = Arc::new(Mutex::new(vec![]));

    let ev_i = session_broadcast::client_1(
        event_loop_i,
        initiator,
        Arc::clone(&session_result),
        session_participants,
    )
    .await?;
    let ev_p_1 = session_broadcast::client_2(
        event_loop_p_1,
        participant_1,
        Arc::clone(&session_result),
    )
    .await?;
    let ev_p_2 = session_broadcast::client_3(
        event_loop_p_2,
        participant_2,
        Arc::clone(&session_result),
    )
    .await?;

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
