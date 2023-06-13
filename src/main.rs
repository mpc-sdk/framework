#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod commands;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod cli {

    use anyhow::Result;
    use clap::{Parser, Subcommand};
    use std::path::PathBuf;

    use super::commands;

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

            /// Write keypair to this file.
            file: PathBuf,
        },

        /// Start the websocket server.
        Start {
            /// Override the reap interval for expired sessions in seconds.
            #[clap(long)]
            reap_interval: Option<u64>,

            /// Override the default session timeout in seconds.
            #[clap(long)]
            session_timeout: Option<u64>,

            /// Bind to host:port.
            #[clap(short, long, default_value = "0.0.0.0:7007")]
            bind: String,

            /// Config file to load.
            #[clap(short, long)]
            config: PathBuf,
        },
    }

    pub(super) async fn run() -> Result<()> {
        let args = RelayServer::parse();
        match args.cmd {
            Command::GenerateKeypair { file, force } => {
                commands::generate_keypair::run(file, force).await?
            }
            Command::Start {
                reap_interval,
                session_timeout,
                bind,
                config,
            } => {
                commands::server::run(
                    reap_interval,
                    session_timeout,
                    bind,
                    config,
                )
                .await?
            }
        }
        Ok(())
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "mpc_relay=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = cli::run().await {
        tracing::error!("{}", e);
    }

    Ok(())
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub fn main() {}
