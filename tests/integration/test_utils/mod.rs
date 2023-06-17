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

use mpc_relay_protocol::{generate_keypair, snow::Keypair};

use mpc_relay_client::{Client, ClientOptions, EventLoop};

/// Create a new client connected to the mock server.
pub async fn new_client<E: From<mpc_relay_client::Error>>(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<(Client, EventLoop, Keypair), E> {
    let keypair = generate_keypair().map_err(|e| {
        let err = mpc_relay_client::Error::from(e);
        err
    })?;
    let copy = Keypair {
        public: keypair.public.clone(),
        private: keypair.public.clone(),
    };
    let options = ClientOptions {
        keypair,
        server_public_key,
    };
    let url = options.url(server);
    let (client, event_loop) = Client::new(&url, options).await?;
    Ok((client, event_loop, copy))
}
