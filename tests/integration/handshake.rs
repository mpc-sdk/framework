use anyhow::Result;
use futures::join;
use serial_test::serial;

use crate::test_utils::{new_client, spawn};

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (initiator, initiator_key) = new_client().await?;
    let (participant, participant_key) = new_client().await?;

    // Both peers must have completed their server handshake
    let (initiator, participant) =
        join!(initiator.handshake(), participant.handshake());

    let mut initiator = initiator?;
    let mut participant = participant?;

    // Now we can perform a peer handshake
    initiator.peer_handshake(&participant_key.public).await?;

    Ok(())
}
