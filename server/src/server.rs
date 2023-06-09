use futures::StreamExt;
use std::{
    collections::HashMap, net::SocketAddr, sync::Arc, time::Duration,
};
use tokio::sync::RwLock;
use tokio_stream::wrappers::IntervalStream;

use axum::{
    extract::Extension,
    http::{HeaderValue, Method},
    routing::get,
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

use mpc_relay_protocol::{snow::Keypair, uuid, SessionManager};

use crate::{
    config::{ServerConfig, TlsConfig},
    Result,
};

use crate::{service::RelayService, websocket::Connection};

pub type State = Arc<RwLock<ServerState>>;
pub(crate) type Service = Arc<RelayService>;

async fn session_reaper(state: State, interval_secs: u64) {
    let interval =
        tokio::time::interval(Duration::from_secs(interval_secs));
    let mut stream = IntervalStream::new(interval);
    while (stream.next().await).is_some() {
        let mut writer = state.write().await;
        let expired_sessions = writer
            .sessions
            .expired_keys(writer.config.session.timeout);
        tracing::debug!(
            expired_sessions = %expired_sessions.len());
        for key in expired_sessions {
            writer.sessions.remove_session(&key);
        }
    }
}

pub struct ServerState {
    /// Server keypair.
    pub(crate) keypair: Keypair,

    /// Server config.
    pub(crate) config: ServerConfig,

    /// Pending socket connections in the handshake state.
    pub(crate) pending: HashMap<Uuid, Connection>,

    /// Active socket connections in the transport state.
    ///
    /// Now the hashmap key is the client's public key.
    pub(crate) active: HashMap<Vec<u8>, Connection>,

    /// Session manager.
    pub(crate) sessions: SessionManager,
}

/// Relay web server.
pub struct RelayServer {
    state: State,
}

impl RelayServer {
    /// Create a new relay server.
    pub fn new(config: ServerConfig, keypair: Keypair) -> Self {
        Self {
            state: Arc::new(RwLock::new(ServerState {
                keypair,
                config,
                pending: Default::default(),
                active: Default::default(),
                sessions: Default::default(),
            })),
        }
    }

    /// Start the server.
    pub async fn start(
        &self,
        addr: SocketAddr,
        handle: Handle,
    ) -> Result<()> {
        let origins = self.read_origins().await?;
        let reader = self.state.read().await;
        let reap_interval = reader.config.session.reap_interval;
        let tls = reader.config.tls.as_ref().cloned();
        drop(reader);

        // Spawn task to reap expired sessions
        tokio::task::spawn(session_reaper(
            Arc::clone(&self.state),
            reap_interval,
        ));

        if let Some(tls) = tls {
            self.run_tls(addr, handle, origins, tls).await
        } else {
            self.run(addr, handle, origins).await
        }
    }

    /// Start the server running on HTTPS.
    async fn run_tls(
        &self,
        addr: SocketAddr,
        handle: Handle,
        origins: Vec<HeaderValue>,
        tls: TlsConfig,
    ) -> Result<()> {
        let tls =
            RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        let app = self.router(Arc::clone(&self.state), origins)?;
        tracing::info!("listening on {}", addr);
        axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    /// Start the server running on HTTP.
    async fn run(
        &self,
        addr: SocketAddr,
        handle: Handle,
        origins: Vec<HeaderValue>,
    ) -> Result<()> {
        let app = self.router(Arc::clone(&self.state), origins)?;
        tracing::info!("listening on {}", addr);
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    fn router(
        &self,
        state: State,
        origins: Vec<HeaderValue>,
    ) -> Result<Router> {
        let cors = CorsLayer::new()
            .allow_methods(vec![Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_headers(vec![])
            .expose_headers(vec![])
            .allow_origin(origins);

        let service = Arc::new(RelayService::new(Arc::clone(&state)));

        let mut app =
            Router::new().route("/", get(crate::websocket::upgrade));
        app = app
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .layer(Extension(service))
            .layer(Extension(state));
        Ok(app)
    }

    async fn read_origins(&self) -> Result<Vec<HeaderValue>> {
        let reader = self.state.read().await;
        let mut origins = Vec::new();
        for url in reader.config.cors.origins.iter() {
            origins.push(HeaderValue::from_str(
                url.as_str().trim_end_matches('/'),
            )?);
        }
        Ok(origins)
    }
}
