pub(crate) mod gg20;

pub(crate) mod peer_channel;
pub(crate) mod session_broadcast;
pub(crate) mod session_handshake;
pub(crate) mod session_timeout;
pub(crate) mod socket_close;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) mod native;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) mod web;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use native::*;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web::*;

use mpc_protocol::{generate_keypair, Keypair};

use mpc_client::{Client, ClientOptions, EventLoop};

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
    };
    let url = options.url(server);
    let (client, event_loop) = Client::new(&url, options).await?;
    Ok((client, event_loop))
}
