use crate::{MeetingState, Result, SessionId, SessionState};
/// Events dispatched by the event loop stream.
#[derive(Debug)]
pub enum Event {
    /// Event dispatched when a handshake with the server
    /// is completed.
    ServerConnected {
        /// Public key of the server.
        server_key: Option<Vec<u8>>,
    },
    /// Event dispatched when a handshake with a peer
    /// has been completed.
    PeerConnected {
        /// Public key of the peer.
        peer_key: Vec<u8>,
    },
    /// Binary message received from a peer.
    BinaryMessage {
        /// Public key of the peer.
        peer_key: Vec<u8>,
        /// Message buffer.
        message: Vec<u8>,
        /// Session identifier.
        session_id: Option<SessionId>,
    },
    /// JSON message received from a peer.
    JsonMessage {
        /// Public key of the peer.
        peer_key: Vec<u8>,
        /// JSON message.
        message: JsonMessage,
        /// Session identifier.
        session_id: Option<SessionId>,
    },

    /// Event dispatched when a meeting has been created.
    MeetingCreated(MeetingState),

    /// Event dispatched when a meeting is ready.
    ///
    /// A meeting is ready when the limit for the meeting point
    /// has been reached.
    MeetingReady(MeetingState),

    /// Event dispatched when a session has been created.
    SessionCreated(SessionState),

    /// Event dispatched when a session is ready.
    ///
    /// A session is ready when all participants
    /// have completed the server handshake.
    ///
    /// Peers can now handshake with each other.
    SessionReady(SessionState),

    /// Event dispatched when a session is active.
    ///
    /// A session is active when all the participants
    /// have connected to each other.
    SessionActive(SessionState),

    /// Event dispatched when a session timed out waiting
    /// for all the participants.
    SessionTimeout(SessionId),

    /// Event dispatched when a session has been finished.
    ///
    /// A session can only be finished when the session owner
    /// explicitly closes the session.
    SessionFinished(SessionId),

    /// Event dispatched when the socket is closed.
    Close,
}

/// JSON message received from a peer.
#[derive(Debug)]
pub struct JsonMessage {
    contents: Vec<u8>,
}

impl From<Vec<u8>> for JsonMessage {
    fn from(contents: Vec<u8>) -> Self {
        Self { contents }
    }
}

impl JsonMessage {
    /// Serialize a message.
    pub fn serialize<T: serde::ser::Serialize>(
        value: &T,
    ) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(value)?)
    }

    /// Deserialize this message.
    pub fn deserialize<'a, T: serde::de::Deserialize<'a>>(
        &'a self,
    ) -> Result<T> {
        Ok(serde_json::from_slice::<T>(&self.contents)?)
    }
}
