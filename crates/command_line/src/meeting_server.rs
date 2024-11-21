//! Command line tool for the websocket relay service that uses the
//! [noise](https://noiseprotocol.org/) protocol for end-to-end
//! encryption intended for multi-party computation and threshold
//! signature applications.

#[doc(hidden)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod meeting;

#[doc(hidden)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod cli {

    use anyhow::Result;
    use clap::{Parser, Subcommand};
    use std::path::PathBuf;

    use super::meeting;

    #[derive(Parser, Debug)]
    #[clap(author, version, about, long_about = None)]
    pub struct MeetingServer {
        #[clap(subcommand)]
        cmd: Command,
    }

    #[derive(Debug, Subcommand)]
    pub enum Command {
        /// Start a relay websocket service.
        Start {
            /// Override the interval to poll for expired sessions in seconds.
            #[clap(long)]
            session_interval: Option<u64>,

            /// Override the default session timeout in seconds.
            #[clap(long)]
            session_timeout: Option<u64>,

            /// Bind to host:port.
            #[clap(short, long, default_value = "0.0.0.0:7070")]
            bind: String,

            /// Config file to load.
            config: PathBuf,
        },
    }

    pub(super) async fn run() -> Result<()> {
        let args = MeetingServer::parse();
        match args.cmd {
            Command::Start {
                session_interval,
                session_timeout,
                bind,
                config,
            } => {
                meeting::start::run(
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
