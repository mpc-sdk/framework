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
    let (mut initiator, initiator_key) = new_client().await?;
    let (participant, participant_key) = new_client().await?;

    println!(
        "initiator public key {}",
        hex::encode(&initiator_key.public)
    );
    println!(
        "participant public key {}",
        hex::encode(&participant_key.public)
    );
    
    // Now we can perform a peer handshake
    initiator.peer_handshake(&participant_key.public).await?;

    std::thread::sleep(Duration::from_millis(2000));
    //loop {}

    Ok(())
}
