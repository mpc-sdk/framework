use mpc_relay_client::{Event, NetworkTransport, Transport};
use mpc_relay_protocol::SessionState;

use crate::{Error, ProtocolDriver, Result, Round, RoundBuffer};
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

impl From<SessionParticipant> for Transport {
    fn from(value: SessionParticipant) -> Self {
        value.transport
    }
}

/// Connects a network transport with a protocol driver.
pub struct Bridge<D: ProtocolDriver> {
    pub(crate) transport: Transport,
    //pub(crate) event_stream: EventStream,
    pub(crate) buffer: RoundBuffer<D::Incoming>,
    pub(crate) driver: D,
    pub(crate) session: SessionState,
}

impl<D: ProtocolDriver> Bridge<D> {
    /// Handle event from the client event loop stream.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<D::Output>> {
        match event {
            Event::JsonMessage {
                message,
                session_id,
                ..
            } => {
                if let Some(session_id) = &session_id {
                    if session_id != &self.session.session_id {
                        return Err(Error::SessionIdMismatch);
                    }
                } else {
                    return Err(Error::SessionIdRequired);
                }

                let message: D::Outgoing = message.deserialize()?;
                let round_number = message.round_number();

                let incoming: D::Incoming = message.into();
                self.buffer.add_message(round_number, incoming);

                if self.buffer.is_ready(round_number) {
                    let messages = self.buffer.take(round_number);
                    for message in messages {
                        // FIXME: do error conversion
                        self.driver.handle_incoming(message).unwrap();
                    }

                    // FIXME: do error conversion
                    let messages =
                        self.driver.proceed().unwrap();
                    self.dispatch_round_messages(messages)
                        .await?;

                    //println!("is ready... {}", round_number.get());

                    if round_number.get() as usize == self.buffer.len() {
                        // FIXME: do error conversion
                        let result = self.driver.finish().unwrap();
                        return Ok(Some(result));
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<()> {
        // FIXME: do error conversion
        let messages = self.driver.proceed().unwrap();
        self.dispatch_round_messages(messages).await?;
        Ok(())
    }

    async fn dispatch_round_messages(
        &mut self,
        mut messages: Vec<D::Outgoing>,
    ) -> Result<()> {
        let is_broadcast = messages.len() == 1
            && messages.get(0).as_ref().unwrap().is_broadcast();

        if is_broadcast {
            let message = messages.remove(0);
            let recipients =
                self.session.recipients(self.transport.public_key());
            self.transport
                .broadcast_json(
                    &self.session.session_id,
                    recipients.as_slice(),
                    &message,
                )
                .await?;
        } else {
            for message in messages {
                let party_number = message.receiver().unwrap();
                let peer_key =
                    self.session.peer_key(*party_number).unwrap();

                self.transport
                    .send_json(
                        peer_key,
                        &message,
                        Some(self.session.session_id),
                    )
                    .await?;
            }
        }

        Ok(())
    }
}
