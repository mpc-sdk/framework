use crate::test_utils::{server_public_key, spawn, SERVER};
use anyhow::Result;
use serial_test::serial;

use mpc_relay_server::{keypair::generate_keypair, NativeClient};

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let public_key = server_public_key().await?;
    let keypair = generate_keypair()?;
    let client = NativeClient::new(SERVER, keypair, public_key).await?;
    let mut client = client.handshake().await?;

    /*
    let message = vec![1; 16];
    let reply = client.send_recv_binary(message).await?;
    println!("{:#?}", reply);
    */

    Ok(())
}
