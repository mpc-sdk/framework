use anyhow::Result;
use serial_test::serial;
use std::time::Duration;

use crate::test_utils::{new_client, spawn};

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    // Wait for the server to start
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    // Create new clients and automatically perform the
    // server handshake
    let (mut initiator, event_loop_i, initiator_key) =
        new_client().await?;
    let (mut participant, event_loop_p, participant_key) =
        new_client().await?;

    let ev_i = tokio::task::spawn(event_loop_i.run());
    let ev_p = tokio::task::spawn(event_loop_p.run());

    initiator.handshake().await?;
    participant.handshake().await?;

    /*
    println!(
        "initiator public key {}",
        hex::encode(&initiator_key.public)
    );
    println!(
        "participant public key {}",
        hex::encode(&participant_key.public)
    );
    */

    // Now we can perform a peer handshake
    initiator.connect_peer(&participant_key.public).await?;

    //std::thread::sleep(Duration::from_millis(20000));

    let (_, _) = futures::join!(ev_i, ev_p);

    //loop {}

    Ok(())
}
