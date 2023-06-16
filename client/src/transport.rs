use async_trait::async_trait;
use mpc_relay_protocol::SessionId;
use serde::Serialize;
use crate::Result;

/// Trait for network clients.
#[async_trait]
pub trait NetworkTransport {
    /// Public key for this client.
    fn public_key(&self) -> &[u8];

    /// Perform initial handshake with the server.
    async fn connect(&mut self) -> Result<()>;

    /// Handshake with a peer.
    ///
    /// Peer already exists error is returned if this
    /// client is already connecting to the peer.
    async fn connect_peer(
        &mut self,
        public_key: &[u8],
    ) -> Result<()>;

    /// Send a JSON message to a peer.
    async fn send_json<S>(
        &mut self,
        public_key: &[u8],
        payload: &S,
        session_id: Option<SessionId>,
    ) -> Result<()>
    where
        S: Serialize + Send + Sync + ?Sized;

    /// Send a binary message to a peer.
    async fn send_blob(
        &mut self,
        public_key: &[u8],
        payload: Vec<u8>,
        session_id: Option<SessionId>,
    ) -> Result<()>;

    /// Create a new session.
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
    
    /// Broadcast a JSON message in the context of a session.
    async fn broadcast_json<S>(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: &[Vec<u8>],
        payload: &S,
    ) -> Result<()>
    where
        S: Serialize + Send + Sync + ?Sized;

    /// Broadcast a binary message in the context of a session.
    async fn broadcast_blob(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: &[Vec<u8>],
        payload: Vec<u8>,
    ) -> Result<()>;
}
