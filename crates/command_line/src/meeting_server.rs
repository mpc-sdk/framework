//! Command line tool for the polysig websocket meeting room service,
//! see [polysig_meeting_server::ServerConfig] for configuration details.
//!
//! # Installation
//!
//! ```no_run
//! cargo install polysig-server
//! ```
//!
//! # Server
//!
//! Start the meeting room websocket service with a default config:
//!
//! ```no_run
//! polysig-meeting
//! ```
//!
//! Or pass a config file:
//!
//! ```no_run
//! polysig-meeting config.toml
//! ```

use anyhow::Result;
use axum_server::Handle;
use clap::Parser;
use polysig_meeting_server::{MeetingServer, ServerConfig};
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr};

/// Meeting room websocket server.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct MeetingService {
    /// Override the interval to poll for expired meeting
    /// rooms in seconds.
    #[clap(long)]
    room_interval: Option<u64>,

    /// Override the default meeting room timeout in seconds.
    #[clap(long)]
    room_timeout: Option<u64>,

    /// Bind to host:port.
    #[clap(short, long, default_value = "0.0.0.0:7070")]
    bind: String,

    /// Config file to load.
    config: Option<PathBuf>,
}

/// Start the server.
async fn start_server(
    bind: String,
    config: Option<PathBuf>,
    interval: Option<u64>,
    timeout: Option<u64>,
) -> Result<()> {
    let mut config = if let Some(path) = config {
        ServerConfig::load(&path).await?
    } else {
        Default::default()
    };

    if let Some(interval) = interval {
        config.session.interval = interval;
    }

    if let Some(timeout) = timeout {
        config.session.timeout = timeout;
    }

    let handle = Handle::new();
    let addr = SocketAddr::from_str(&bind)?;
    let server = MeetingServer::new(config);
    server.start(addr, handle).await?;
    Ok(())
}

async fn run() -> Result<()> {
    let args = MeetingService::parse();
    start_server(
        args.bind,
        args.config,
        args.room_interval,
        args.room_timeout,
    )
    .await?;
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
                "polysig_meeting_server=info".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run().await {
        tracing::error!("{}", e);
    }

    Ok(())
}
