//! Command line tool for the polysig websocket relay service that
//! uses the [noise](https://noiseprotocol.org/) protocol for end-to-end
//! encryption intended for multi-party computation and threshold
//! signature applications.
//!
//! See [polysig_relay_server::ServerConfig] for configuration details.
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
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use anyhow::{bail, Result};
use axum_server::Handle;
use clap::{Parser, Subcommand};
use polysig_protocol::hex;
use polysig_relay_server::{RelayServer, ServerConfig};
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr};
use tokio::{fs, io::AsyncWriteExt};

/// Relay websocket server.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RelayService {
    #[clap(subcommand)]
    cmd: Command,
}

/// Program commands.
#[derive(Debug, Subcommand)]
enum Command {
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

/// Generate keypair and write to file.
async fn generate_keypair(
    path: PathBuf,
    force: bool,
    public_key: Option<PathBuf>,
) -> Result<()> {
    if fs::try_exists(&path).await? && !force {
        bail!(
            "file {} already exists, use --force to overwrite",
            path.display()
        );
    }

    let keypair = polysig_protocol::generate_keypair()?;
    let pem = polysig_protocol::encode_keypair(&keypair);

    let mut file = fs::File::create(&path).await?;
    file.write_all(pem.as_bytes()).await?;
    file.flush().await?;

    println!("{}", hex::encode(keypair.public_key()));

    if let Some(public_key) = public_key {
        let public_key_hex = hex::encode(keypair.public_key());
        fs::write(public_key, public_key_hex.as_bytes()).await?;
    }

    Ok(())
}

/// Start the web server.
async fn start_server(
    bind: String,
    config: PathBuf,
    interval: Option<u64>,
    session_timeout: Option<u64>,
) -> Result<()> {
    let (mut config, keypair) = ServerConfig::load(&config).await?;

    if let Some(interval) = interval {
        config.session.interval = interval;
    }

    if let Some(session_timeout) = session_timeout {
        config.session.timeout = session_timeout;
    }

    let handle = Handle::new();
    let addr = SocketAddr::from_str(&bind)?;
    let server = RelayServer::new(config, keypair);
    server.start(addr, handle).await?;
    Ok(())
}

/// Parse arguments and run the program.
async fn run() -> Result<()> {
    let args = RelayService::parse();
    match args.cmd {
        Command::GenerateKeypair {
            file,
            force,
            public_key,
        } => generate_keypair(file, force, public_key).await?,
        Command::Start {
            session_interval,
            session_timeout,
            bind,
            config,
        } => {
            start_server(
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

#[doc(hidden)]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "polysig_relay_server=info".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run().await {
        tracing::error!("{}", e);
    }

    Ok(())
}
