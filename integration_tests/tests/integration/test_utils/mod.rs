#[cfg(feature = "cggmp")]
pub(crate) mod cggmp;

pub(crate) mod meeting_point;
pub(crate) mod peer_channel;
pub(crate) mod session_broadcast;
#[cfg(any(feature = "cggmp", feature = "frost-ed25519"))]
pub(crate) mod session_handshake;
pub(crate) mod session_timeout;
pub(crate) mod socket_close;

pub(crate) mod native;
pub use native::*;

use mpc_client::{Client, ClientOptions, EventLoop};
use mpc_protocol::{generate_keypair, Keypair};

/// Create a new client connected to the mock server.
pub async fn new_client<E: From<mpc_client::Error>>(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<(Client, EventLoop, Keypair), E> {
    let keypair = generate_keypair().map_err(|e| {
        let err = mpc_client::Error::from(e);
        err
    })?;
    let copy = keypair.clone();
    let (client, event_loop) =
        new_client_with_keypair(server, server_public_key, keypair)
            .await?;
    Ok((client, event_loop, copy))
}

pub async fn new_client_with_keypair<E: From<mpc_client::Error>>(
    server: &str,
    server_public_key: Vec<u8>,
    keypair: Keypair,
) -> Result<(Client, EventLoop), E> {
    let options = ClientOptions {
        keypair,
        server_public_key,
        pattern: None,
    };
    let url = options.url(server);
    let (client, event_loop) = Client::new(&url, options).await?;
    Ok((client, event_loop))
}
