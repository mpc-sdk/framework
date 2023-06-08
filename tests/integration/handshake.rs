use crate::test_utils::{init_tracing, new_client, spawn};
use anyhow::Result;
use futures::StreamExt;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    init_tracing();

    // Wait for the server to start
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    // Create new clients and automatically perform the
    // server handshake
    let (mut initiator, mut event_loop_i, _initiator_key) =
        new_client().await?;
    let (mut participant, mut event_loop_p, participant_key) =
        new_client().await?;

    let ev_i = tokio::task::spawn(async move {
        let mut s = event_loop_i.run();
        while let Some(event) = s.next().await {
            let event = event?;
            tracing::info!("initiator {:#?}", event);
        }
        Ok::<(), anyhow::Error>(())
    });

    let ev_p = tokio::task::spawn(async move {
        let mut s = event_loop_p.run();
        while let Some(event) = s.next().await {
            let event = event?;
            tracing::info!("participant {:#?}", event);
        }
        Ok::<(), anyhow::Error>(())
    });

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

    // Must drive the event loop futures
    let (_, _) = futures::join!(ev_i, ev_p);

    Ok(())
}
