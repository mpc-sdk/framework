//! Server configuration.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use url::Url;

use crate::{Error, Result};

/// Configuration for the web server.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Settings for session management.
    pub session: SessionConfig,

    /// Configuration for TLS encryption.
    pub tls: Option<TlsConfig>,

    /// Configuration for CORS.
    pub cors: CorsConfig,
}

/// Certificate and key for TLS.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate.
    pub cert: PathBuf,
    /// Path to the certificate key file.
    pub key: PathBuf,
}

/// Configuration for server sessions.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SessionConfig {
    /// Timeout for sessions in seconds.
    ///
    /// Sessions that have not seen any message activity
    /// for this amount of time are marked for deletion.
    ///
    /// Default is 5 minutes.
    pub timeout: u64,

    /// Interval in seconds to reap expired sessions.
    ///
    /// Default is every 15 minutes.
    pub interval: u64,

    /// The interval used to poll a session for the ready
    /// and active states.
    ///
    /// A session is ready when all participants have completed
    /// the server handshake and is active when all participants
    /// have established their peer connections.
    ///
    /// Default is 15 seconds.
    pub wait_interval: u64,

    /// Wait timeout controls the timeout when waiting
    /// for all clients in a session to become active.
    ///
    /// Default is 5 minutes.
    pub wait_timeout: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: 300,
            interval: 900,
            wait_interval: 15,
            wait_timeout: 300,
        }
    }
}

impl ServerConfig {
    /// Load a server config from a file path.
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !fs::try_exists(path.as_ref()).await? {
            return Err(Error::NotFile(path.as_ref().to_path_buf()));
        }

        let contents = fs::read_to_string(path.as_ref()).await?;
        let mut config: ServerConfig = toml::from_str(&contents)?;

        if config.session.interval <= config.session.timeout {
            return Err(Error::SessionTimeoutConfig);
        }

        if config.session.wait_timeout <= config.session.wait_interval
        {
            return Err(Error::SessionWaitConfig);
        }

        let dir = Self::directory(path.as_ref())?;
        if let Some(tls) = config.tls.as_mut() {
            if tls.cert.is_relative() {
                tls.cert = dir.join(&tls.cert).canonicalize()?;
            }
            if tls.key.is_relative() {
                tls.key = dir.join(&tls.key).canonicalize()?;
            }
        }

        Ok(config)
    }

    /// Parent directory of the configuration file.
    fn directory(file: impl AsRef<Path>) -> Result<PathBuf> {
        file.as_ref()
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| Error::NoParentDir)
    }
}

/// Configuration for CORS.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CorsConfig {
    /// List of additional CORS origins for the server.
    pub origins: Vec<Url>,
}
