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
    /// Timeout for meeting rooms in seconds.
    ///
    /// Meeting rooms that have not seen any message activity
    /// for this amount of time are marked for deletion.
    ///
    /// Default is 5 minutes.
    pub timeout: u64,

    /// Interval in seconds to reap expired meeting rooms.
    ///
    /// Default is every 15 minutes.
    pub interval: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: 300,
            interval: 900,
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
