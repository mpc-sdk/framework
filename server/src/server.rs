use futures::StreamExt;
use std::{
    collections::HashMap, net::SocketAddr, sync::Arc, time::Duration,
};
use tokio::sync::RwLock;
use tokio_stream::wrappers::IntervalStream;

use axum::{extract::Extension, routing::get, Router};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use mpc_protocol::{
    hex, uuid, Keypair, MeetingManager, SessionManager,
};

use crate::{
    config::{ServerConfig, TlsConfig},
    Result,
};

use crate::{service::RelayService, websocket::Connection};

pub type State = Arc<RwLock<ServerState>>;
pub(crate) type Service = Arc<RelayService>;

async fn purge_expired(state: State, interval_secs: u64) {
    let interval =
        tokio::time::interval(Duration::from_secs(interval_secs));
    let mut stream = IntervalStream::new(interval);
    while stream.next().await.is_some() {
        let mut writer = state.write().await;
        let expired_meetings = writer
            .meetings
            .expired_keys(writer.config.session.timeout);
        tracing::debug!(
            expired_meetings = %expired_meetings.len());
        for key in expired_meetings {
            writer.meetings.remove_meeting(&key);
        }

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

    /// Meeting point manager.
    pub(crate) meetings: MeetingManager,

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
                meetings: Default::default(),
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
        let reader = self.state.read().await;
        let interval = reader.config.session.interval;
        let tls = reader.config.tls.as_ref().cloned();
        drop(reader);

        // Spawn task to reap expired sessions
        tokio::task::spawn(purge_expired(
            Arc::clone(&self.state),
            interval,
        ));

        if let Some(tls) = tls {
            self.run_tls(addr, handle, tls).await
        } else {
            self.run(addr, handle).await
        }
    }

    /// Start the server running on HTTPS.
    async fn run_tls(
        &self,
        addr: SocketAddr,
        handle: Handle,
        tls: TlsConfig,
    ) -> Result<()> {
        let tls =
            RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        let app = self.router(Arc::clone(&self.state))?;
        let public_key = {
            let reader = self.state.read().await;
            reader.keypair.public_key().to_vec()
        };
        tracing::info!("listening on {}", addr);
        tracing::info!("public key {}", hex::encode(&public_key));
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
    ) -> Result<()> {
        let app = self.router(Arc::clone(&self.state))?;
        let public_key = {
            let reader = self.state.read().await;
            reader.keypair.public_key().to_vec()
        };
        tracing::info!("listening on {}", addr);
        tracing::info!("public key {}", hex::encode(&public_key));
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    fn router(&self, state: State) -> Result<Router> {
        let service = Arc::new(RelayService::new(Arc::clone(&state)));
        let mut app =
            Router::new().route("/", get(crate::websocket::upgrade));
        app = app
            .layer(TraceLayer::new_for_http())
            .layer(Extension(service))
            .layer(Extension(state));
        Ok(app)
    }
}
