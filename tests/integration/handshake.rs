use crate::test_utils::{spawn, SERVER};
use anyhow::Result;
use serial_test::serial;

use mpc_relay_server::NativeClient;

#[tokio::test]
#[serial]
async fn integration_handshake() -> Result<()> {
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let mut client = NativeClient::new(SERVER).await?;
    let message = vec![1; 16];
    client.send_binary(message).await?;

    Ok(())
}
