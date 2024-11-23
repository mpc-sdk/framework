//! Command line tool for the polysig websocket relay service that
//! uses the [noise](https://noiseprotocol.org/) protocol for end-to-end
//! encryption intended for multi-party computation and threshold
//! signature applications.
//!
//! # Installation
//!
//! ```no_run
//! cargo install polysig-server
//! ```
//! # Generate keypair
//!
//! First generate a keypair for the server:
//!
//! ```no_run
//! polysig-relay generate-keypair server.pem
//! ```
//!
//! # Configuration
//!
//! Then create a configuration file for the server (`config.toml`):
//!
//! ```no_run
//! key = "server.pem"
//! ```
//!
//! # Server
//!
//! Start the relay websocket service:
//!
//! ```no_run
//! polysig-relay start config.toml
//! ```

#[doc(hidden)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod relay;

#[doc(hidden)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod cli {

    use anyhow::Result;
    use clap::{Parser, Subcommand};
    use std::path::PathBuf;

    use super::relay;

    #[derive(Parser, Debug)]
    #[clap(author, version, about, long_about = None)]
    pub struct RelayServer {
        #[clap(subcommand)]
        cmd: Command,
    }

    #[derive(Debug, Subcommand)]
    pub enum Command {
        /// Generate PEM-encoded keypair and write to file.
        GenerateKeypair {
            /// Force overwrite if the file exists.
            #[clap(short, long)]
            force: bool,

            /// Write hex-encoded public key to a file.
            #[clap(long)]
            public_key: Option<PathBuf>,

            /// Write keypair to this file.
            file: PathBuf,
        },

        /// Start a relay websocket service.
        Start {
            /// Override the interval to poll for expired sessions in seconds.
            #[clap(long)]
            session_interval: Option<u64>,

            /// Override the default session timeout in seconds.
            #[clap(long)]
            session_timeout: Option<u64>,

            /// Bind to host:port.
            #[clap(short, long, default_value = "0.0.0.0:7007")]
            bind: String,

            /// Config file to load.
            config: PathBuf,
        },
    }

    pub(super) async fn run() -> Result<()> {
        let args = RelayServer::parse();
        match args.cmd {
            Command::GenerateKeypair {
                file,
                force,
                public_key,
            } => {
                relay::generate_keypair::run(file, force, public_key)
                    .await?
            }
            Command::Start {
                session_interval,
                session_timeout,
                bind,
                config,
            } => {
                relay::start::run(
                    bind,
                    config,
                    session_interval,
                    session_timeout,
                )
                .await?
            }
        }
        Ok(())
    }
}

#[doc(hidden)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "polysig_server=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = cli::run().await {
        tracing::error!("{}", e);
    }

    Ok(())
}

#[doc(hidden)]
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub fn main() {}
