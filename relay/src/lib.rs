mod client;
pub mod constants;
mod error;
pub mod keypair;
mod protocol;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod server;

pub use client::{ClientOptions, Event};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use client::{EventLoop, NativeClient};

pub use error::Error;
pub(crate) use protocol::{
    decode, encode, HandshakeType, PeerMessage, ProtocolState,
    RequestMessage, ResponseMessage,
};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use server::{config::ServerConfig, RelayServer};

pub type Result<T> = std::result::Result<T, Error>;
