use crate::{Client, ClientOptions, EventLoop, Result};
use async_trait::async_trait;
use mpc_protocol::{serde_json::Value, MeetingId, SessionId, UserId};
use serde::Serialize;
use std::collections::HashSet;

/// Enumeration of available transports.
#[derive(Clone)]
pub enum Transport {
    /// Relay websocket client.
    Relay(Client),
    // NOTE: later we will add a Peer variant using
    // NOTE: a WebRTC data channel for communication
}

impl From<Client> for Transport {
    fn from(value: Client) -> Self {
        Self::Relay(value)
    }
}

#[async_trait]
impl NetworkTransport for Transport {
    fn public_key(&self) -> &[u8] {
        match self {
            Transport::Relay(client) => client.public_key(),
        }
    }

    async fn connect(&mut self) -> Result<()> {
        match self {
            Transport::Relay(client) => client.connect().await,
        }
    }

    async fn is_connected(&self) -> bool {
        match self {
            Transport::Relay(client) => client.is_connected().await,
        }
    }

    async fn connect_peer(
        &mut self,
        public_key: &[u8],
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client.connect_peer(public_key).await
            }
        }
    }

    async fn send_json<S>(
        &mut self,
        public_key: &[u8],
        payload: &S,
        session_id: Option<SessionId>,
    ) -> Result<()>
    where
        S: Serialize + Send + Sync,
    {
        match self {
            Transport::Relay(client) => {
                client
                    .send_json(public_key, payload, session_id)
                    .await
            }
        }
    }

    async fn send_blob(
        &mut self,
        public_key: &[u8],
        payload: Vec<u8>,
        session_id: Option<SessionId>,
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client
                    .send_blob(public_key, payload, session_id)
                    .await
            }
        }
    }

    async fn new_meeting(
        &mut self,
        owner_id: UserId,
        slots: HashSet<UserId>,
        data: Value,
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client.new_meeting(owner_id, slots, data).await
            }
        }
    }

    async fn join_meeting(
        &mut self,
        meeting_id: MeetingId,
        user_id: UserId,
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client.join_meeting(meeting_id, user_id).await
            }
        }
    }

    async fn new_session(
        &mut self,
        participant_keys: Vec<Vec<u8>>,
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client.new_session(participant_keys).await
            }
        }
    }

    async fn register_connection(
        &mut self,
        session_id: &SessionId,
        peer_key: &[u8],
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client.register_connection(session_id, peer_key).await
            }
        }
    }

    async fn close_session(
        &mut self,
        session_id: SessionId,
    ) -> Result<()> {
        match self {
            Transport::Relay(client) => {
                client.close_session(session_id).await
            }
        }
    }

    async fn close(&self) -> Result<()> {
        match self {
            Transport::Relay(client) => client.close().await,
        }
    }
}

impl Transport {
    /// Create a new relay client.
    pub async fn new_relay(
        server: &str,
        options: ClientOptions,
    ) -> Result<(Self, EventLoop)> {
        let (client, event_loop) =
            Client::new(server, options).await?;
        Ok((Self::Relay(client), event_loop))
    }
}

/// Trait for network clients.
#[async_trait]
pub trait NetworkTransport {
    /// Public key for this client.
    fn public_key(&self) -> &[u8];

    /// Perform initial handshake with the server.
    async fn connect(&mut self) -> Result<()>;

    /// Determine if this client has completed a
    /// server handshake.
    async fn is_connected(&self) -> bool;

    /// Handshake with a peer.
    ///
    /// Peer already exists error is returned if this
    /// client is already connecting to the peer.
    async fn connect_peer(&mut self, public_key: &[u8])
        -> Result<()>;

    /// Send a JSON message to a peer.
    async fn send_json<S>(
        &mut self,
        public_key: &[u8],
        payload: &S,
        session_id: Option<SessionId>,
    ) -> Result<()>
    where
        S: Serialize + Send + Sync;

    /// Send a binary message to a peer.
    async fn send_blob(
        &mut self,
        public_key: &[u8],
        payload: Vec<u8>,
        session_id: Option<SessionId>,
    ) -> Result<()>;

    /// Create a new meeting point.
    async fn new_meeting(
        &mut self,
        owner_id: UserId,
        slots: HashSet<UserId>,
        data: Value,
    ) -> Result<()>;

    /// Join a meeting point.
    async fn join_meeting(
        &mut self,
        meeting_id: MeetingId,
        user_id: UserId,
    ) -> Result<()>;

    /// Create a new session.
    ///
    /// Do not include the public key of the initiator for the new
    /// session; it is automatically included as the session owner.
    async fn new_session(
        &mut self,
        participant_keys: Vec<Vec<u8>>,
    ) -> Result<()>;

    /// Register a peer connection in a session.
    async fn register_connection(
        &mut self,
        session_id: &SessionId,
        peer_key: &[u8],
    ) -> Result<()>;

    /// Close a session.
    async fn close_session(
        &mut self,
        session_id: SessionId,
    ) -> Result<()>;

    /// Close the socket connection.
    async fn close(&self) -> Result<()>;
}
