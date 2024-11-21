//! Start the websocket meeting server.
use anyhow::Result;
use axum_server::Handle;
use polysig_meeting_server::{MeetingServer, ServerConfig};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

/// Run a web server.
pub async fn run(
    bind: String,
    config: PathBuf,
    interval: Option<u64>,
    session_timeout: Option<u64>,
) -> Result<()> {
    let mut config = ServerConfig::load(&config).await?;

    if let Some(interval) = interval {
        config.session.interval = interval;
    }

    if let Some(session_timeout) = session_timeout {
        config.session.timeout = session_timeout;
    }

    let handle = Handle::new();
    let addr = SocketAddr::from_str(&bind)?;
    let server = MeetingServer::new(config);
    server.start(addr, handle).await?;
    Ok(())
}
