use crate::Result;
use async_trait::async_trait;
use futures::{select, FutureExt, StreamExt};
use mpc_protocol::{SessionId, SessionState};
use mpc_relay_client::{
    Event, EventStream, NetworkTransport, Transport,
};
use tokio::sync::Mutex;

/// Trait for types that handle session related events.
#[async_trait]
pub trait SessionEventHandler {
    /// Handle an event.
    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<SessionState>>;
}

/// Initiate a session.
pub struct SessionInitiator {
    transport: Transport,
    session_participants: Vec<Vec<u8>>,
    session_state: Mutex<Option<SessionState>>,
    session_id: Option<SessionId>,
}

impl SessionInitiator {
    /// Create a new session handshake.
    pub fn new(
        transport: Transport,
        session_participants: Vec<Vec<u8>>,
        session_id: Option<SessionId>,
    ) -> Self {
        Self {
            transport,
            session_participants,
            session_state: Mutex::new(None),
            session_id,
        }
    }
}

#[async_trait]
impl SessionEventHandler for SessionInitiator {
    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<SessionState>> {
        match event {
            Event::ServerConnected { .. } => {
                self.transport
                    .new_session(
                        self.session_participants.clone(),
                        self.session_id.take(),
                    )
                    .await?;
            }
            Event::SessionCreated(session) => {
                tracing::info!(
                    id = ?session.session_id.to_string(),
                    "session created");

                let mut state = self.session_state.lock().await;
                *state = Some(session);
            }
            Event::SessionReady(session) => {
                tracing::info!(
                    id = ?session.session_id.to_string(),
                    "session ready");

                let connections =
                    session.connections(self.transport.public_key());

                for key in connections {
                    self.transport.connect_peer(key).await?;
                }
            }
            Event::PeerConnected { peer_key } => {
                let state = self.session_state.lock().await;
                let session = state.as_ref().unwrap();
                let connections =
                    session.connections(self.transport.public_key());
                if connections.contains(&peer_key) {
                    self.transport
                        .register_connection(
                            &session.session_id,
                            peer_key.as_slice(),
                        )
                        .await?;
                }
            }
            Event::SessionActive(session) => {
                return Ok(Some(session))
            }
            _ => {}
        }
        Ok(None)
    }
}

impl From<SessionInitiator> for Transport {
    fn from(value: SessionInitiator) -> Self {
        value.transport
    }
}

/// Participate in a session.
pub struct SessionParticipant {
    transport: Transport,
    session_state: Mutex<Option<SessionState>>,
}

impl SessionParticipant {
    /// Create a new session participant.
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            session_state: Mutex::new(None),
        }
    }
}

#[async_trait]
impl SessionEventHandler for SessionParticipant {
    /// Handle joining a session for a participant.
    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<SessionState>> {
        match event {
            Event::SessionReady(session) => {
                let mut state = self.session_state.lock().await;
                *state = Some(session.clone());

                tracing::info!(
                    id = ?session.session_id.to_string(),
                    "session ready");

                for key in
                    session.connections(self.transport.public_key())
                {
                    self.transport.connect_peer(key).await?;
                }
            }
            Event::PeerConnected { peer_key } => {
                let state = self.session_state.lock().await;
                let session = state.as_ref().unwrap();
                let connections =
                    session.connections(self.transport.public_key());
                if connections.contains(&peer_key) {
                    self.transport
                        .register_connection(
                            &session.session_id,
                            peer_key.as_slice(),
                        )
                        .await?;
                }
            }
            Event::SessionActive(session) => {
                return Ok(Some(session));
            }
            _ => {}
        }

        Ok(None)
    }
}

impl From<SessionParticipant> for Transport {
    fn from(value: SessionParticipant) -> Self {
        value.transport
    }
}

/// Wait for a session to become active.
pub async fn wait_for_session<S>(
    stream: &mut EventStream,
    mut client_session: S,
) -> Result<(Transport, SessionState)>
where
    S: SessionEventHandler + Into<Transport>,
{
    #[allow(unused_assignments)]
    let mut session: Option<SessionState> = None;
    loop {
        select! {
            event = stream.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(active_session) =
                            client_session.handle_event(event).await? {
                            session = Some(active_session);
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }
    Ok((client_session.into(), session.take().unwrap()))
}
