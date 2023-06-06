pub mod constants;
mod error;
pub mod keypair;
mod server;
mod transport;

pub use error::Error;
pub use server::{config::ServerConfig, RelayServer};

pub type Result<T> = std::result::Result<T, Error>;
