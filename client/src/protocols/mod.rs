use crate::{Client, ClientOptions, EventLoop, Result, Transport};
use async_trait::async_trait;
use mpc_driver::SessionOptions;
use mpc_protocol::{hex, Event};

mod bridge;
mod session;

#[cfg(feature = "cggmp")]
pub mod cggmp;

#[cfg(feature = "frost-ed25519")]
pub mod frost;

pub(crate) use bridge::Bridge;
pub use bridge::{
    wait_for_close, wait_for_driver, wait_for_session_finish,
};

pub use session::{
    wait_for_session, SessionEventHandler, SessionHandler,
    SessionInitiator, SessionParticipant,
};

/// Drives a protocol to completion bridging between
/// the network transport and local computation.
#[async_trait]
pub trait Driver {
    /// Output yielded when the driver completes.
    type Output;

    /// Handle an incoming event.
    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Self::Output>>;

    /// Start running the protocol.
    async fn execute(&mut self) -> Result<()>;

    /// Consume this driver into the underlying transport.
    fn into_transport(self) -> Transport;
}

/// Create a new client using the provided session options.
pub(crate) async fn new_client(
    options: SessionOptions,
) -> Result<(Client, EventLoop)> {
    let server_url = options.server.server_url;
    let options = ClientOptions {
        keypair: options.keypair,
        server_public_key: options.server.server_public_key,
        pattern: options.server.pattern,
    };
    let url = options.url(&server_url);
    Ok(Client::new(&url, options).await?)
}

pub(crate) fn public_key_to_str(public_key: &[u8]) -> String {
    hex::encode(&public_key[0..6])
}
