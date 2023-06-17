use mpc_relay_client::{
    Event, EventStream, NetworkTransport, Transport,
};
use mpc_relay_protocol::SessionState;

use crate::{ProtocolDriver, Result, RoundBuffer};
use tokio::sync::Mutex;

/// Initiate a session.
pub struct SessionInitiator {
    transport: Transport,
    session_participants: Vec<Vec<u8>>,
    session_state: Mutex<Option<SessionState>>,
}

impl SessionInitiator {
    /// Create a new session handshake.
    pub fn new(
        transport: Transport,
        session_participants: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            transport,
            session_participants,
            session_state: Mutex::new(None),
        }
    }

    /// Handle session creation for an initiator.
    pub async fn create(
        &mut self,
        event: Event,
    ) -> Result<Option<SessionState>> {
        match event {
            Event::ServerConnected { .. } => {
                self.transport
                    .new_session(self.session_participants.clone())
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

    /// Handle joining a session for a participant.
    pub async fn join(
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

/// Connects a network transport with a protocol driver.
pub struct Bridge<I, D: ProtocolDriver> {
    pub(crate) transport: Transport,
    pub(crate) event_stream: EventStream,
    pub(crate) buffer: RoundBuffer<I>,
    pub(crate) driver: D,
}

impl<I, D: ProtocolDriver> Bridge<I, D> {
    /// Run the protocol to completion.
    pub async fn execute(&mut self) -> Result<D::Output> {
        //self.phase = BridgePhase::Driver(driver);
        todo!("drive protocol driver to completion");
    }
}
