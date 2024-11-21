use futures::StreamExt;
use std::{net::SocketAddr, sync::Arc, time::Duration};
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

use crate::{
    config::{ServerConfig, TlsConfig},
    meeting_manager::MeetingManager,
    Result,
};

pub type State = Arc<RwLock<ServerState>>;

/*
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
*/

pub struct ServerState {
    /// Server config.
    pub(crate) config: ServerConfig,

    /// Meeting point manager.
    pub(crate) meetings: MeetingManager,
}

/// Relay web server.
pub struct MeetingServer {
    state: State,
}

impl MeetingServer {
    /// Create a new relay server.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(ServerState {
                config,
                meetings: Default::default(),
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
        // let interval = reader.config.session.interval;
        let tls = reader.config.tls.as_ref().cloned();
        drop(reader);

        /*
        // Spawn task to reap expired sessions
        tokio::task::spawn(purge_expired(
            Arc::clone(&self.state),
            interval,
        ));
        */

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
        let app = self.router(Arc::clone(&self.state)).await?;
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
    ) -> Result<()> {
        let app = self.router(Arc::clone(&self.state)).await?;
        tracing::info!("listening on {}", addr);
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    async fn router(&self, state: State) -> Result<Router> {
        let origins = {
            let reader = state.read().await;
            let mut origins = Vec::new();
            for url in reader.config.cors.origins.iter() {
                tracing::info!(url = %url, "cors");
                origins.push(HeaderValue::from_str(
                    url.as_str().trim_end_matches('/'),
                )?);
            }
            origins
        };

        let cors = CorsLayer::new()
            .allow_methods(vec![Method::GET])
            //.allow_headers(vec![])
            //.expose_headers(vec![])
            .allow_origin(origins);

        let mut app =
            Router::new().route("/", get(crate::websocket::upgrade));
        app = app
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .layer(Extension(state));
        Ok(app)
    }
}
