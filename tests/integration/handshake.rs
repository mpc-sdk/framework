use anyhow::Result;
use futures::join;
use serial_test::serial;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::test_utils::{new_client, spawn};

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (client1, _) = new_client().await?;
    let (client2, _) = new_client().await?;

    let (_client1, _client2) =
        join!(client1.handshake(), client2.handshake());

    //let mut client = client.handshake().await?;

    /*
    let message = vec![1; 16];
    let reply = client.send_recv_binary(message).await?;
    println!("{:#?}", reply);
    */

    Ok(())
}
