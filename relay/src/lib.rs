mod client;
pub mod constants;
mod error;
pub mod keypair;
mod protocol;
mod server;
mod transport;

pub use client::{ClientOptions, EventLoop, NativeClient};
pub use error::Error;
pub(crate) use protocol::{
    decode, encode, HandshakeType, PeerMessage, ProtocolState,
    RequestMessage, ResponseMessage,
};
pub use server::{config::ServerConfig, RelayServer};

pub type Result<T> = std::result::Result<T, Error>;
