use anyhow::Result;
use axum_server::Handle;
use mpc_relay_server::{RelayServer, ServerConfig};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

/// Run a web server.
pub async fn run(
    reap_interval: Option<u64>,
    session_duration: Option<u64>,
    bind: String,
    config: PathBuf,
) -> Result<()> {
    let (mut config, keypair) = ServerConfig::load(&config).await?;

    if let Some(reap_interval) = reap_interval {
        config.session.reap_interval = reap_interval;
    }

    if let Some(session_duration) = session_duration {
        config.session.duration = session_duration;
    }

    let handle = Handle::new();
    let addr = SocketAddr::from_str(&bind)?;
    let server = RelayServer::new(config, keypair);
    server.start(addr, handle).await?;
    Ok(())
}
