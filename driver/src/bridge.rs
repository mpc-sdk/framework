use mpc_relay_client::{Event, NetworkTransport, Transport};
use mpc_relay_protocol::{SessionId, SessionState};

use crate::{Error, ProtocolDriver, Round, RoundBuffer};
use tokio::sync::Mutex;

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

    /// Handle session creation for an initiator.
    pub async fn create(
        &mut self,
        event: Event,
    ) -> crate::Result<Option<SessionState>> {
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

    /// Handle joining a session for a participant.
    pub async fn join(
        &mut self,
        event: Event,
    ) -> crate::Result<Option<SessionState>> {
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
pub(crate) struct Bridge<D: ProtocolDriver> {
    pub(crate) transport: Transport,
    pub(crate) buffer: RoundBuffer<D::Incoming>,
    pub(crate) driver: Option<D>,
    pub(crate) session: SessionState,
}

impl<D: ProtocolDriver> Bridge<D> {
    /// Handle event from the client event loop stream.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<D::Output>, D::Error> {
        if let Event::JsonMessage {
            message,
            session_id,
            ..
        } = event
        {
            if let Some(session_id) = &session_id {
                if session_id != &self.session.session_id {
                    return Err(
                        Box::new(Error::SessionIdMismatch).into()
                    );
                }
            } else {
                return Err(Box::new(Error::SessionIdRequired).into());
            }

            let message: D::Outgoing = message.deserialize()?;
            let round_number = message.round_number();
            let incoming: D::Incoming = message.into();
            self.buffer.add_message(round_number, incoming);

            if self.buffer.is_ready(round_number) {
                let messages = self.buffer.take(round_number);
                for message in messages {
                    self.driver
                        .as_mut()
                        .unwrap()
                        .handle_incoming(message)?;
                }

                // For single round drivers we mustn't call proceed again
                if self.buffer.len() == 1 {
                    let result =
                        self.driver.take().unwrap().finish()?;
                    return Ok(Some(result));
                }

                let messages =
                    self.driver.as_mut().unwrap().proceed()?;
                self.dispatch_round_messages(messages).await?;

                if round_number.get() as usize == self.buffer.len() {
                    let result =
                        self.driver.take().unwrap().finish()?;
                    return Ok(Some(result));
                }
            }
        }

        Ok(None)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<(), D::Error> {
        let messages = self.driver.as_mut().unwrap().proceed()?;
        self.dispatch_round_messages(messages).await?;
        Ok(())
    }

    async fn dispatch_round_messages(
        &mut self,
        mut messages: Vec<D::Outgoing>,
    ) -> Result<(), D::Error> {
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
