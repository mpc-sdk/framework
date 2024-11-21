use crate::{encoding::types, PartyNumber, Result, TAGLEN};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snow::{HandshakeState, TransportState};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};

/// Identifier for meeting points.
pub type MeetingId = uuid::Uuid;

/// Identifier for sessions.
pub type SessionId = uuid::Uuid;

/// User identifier wraps an SHA-256 hash of a
/// unique arbitrary value.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct UserId([u8; 32]);

impl AsRef<[u8; 32]> for UserId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for UserId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Parameters used during key generation.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Parameters {
    /// Number of parties `n`.
    pub parties: u16,
    /// Threshold for signing `t`.
    ///
    /// The threshold must be crossed (`t + 1`) for signing
    /// to commence.
    pub threshold: u16,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            parties: 3,
            threshold: 1,
        }
    }
}

/// Enumeration of protocol states.
pub enum ProtocolState {
    /// Noise handshake state.
    Handshake(Box<HandshakeState>),
    /// Noise transport state.
    Transport(TransportState),
}

/// Handshake messages.
#[derive(Default, Debug)]
pub enum HandshakeMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Handshake initiator.
    Initiator(usize, Vec<u8>),
    /// Handshake responder.
    Responder(usize, Vec<u8>),
}

impl From<&HandshakeMessage> for u8 {
    fn from(value: &HandshakeMessage) -> Self {
        match value {
            HandshakeMessage::Noop => types::NOOP,
            HandshakeMessage::Initiator(_, _) => {
                types::HANDSHAKE_INITIATOR
            }
            HandshakeMessage::Responder(_, _) => {
                types::HANDSHAKE_RESPONDER
            }
        }
    }
}

/// Transparent messages are not encrypted.
#[derive(Default, Debug)]
pub enum TransparentMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Return an error message to the client.
    Error(StatusCode, String),
    /// Handshake message.
    ServerHandshake(HandshakeMessage),
    /// Relayed peer handshake message.
    PeerHandshake {
        /// Public key of the receiver.
        public_key: Vec<u8>,
        /// Handshake message.
        message: HandshakeMessage,
    },
}

impl From<&TransparentMessage> for u8 {
    fn from(value: &TransparentMessage) -> Self {
        match value {
            TransparentMessage::Noop => types::NOOP,
            TransparentMessage::Error(_, _) => types::ERROR,
            TransparentMessage::ServerHandshake(_) => {
                types::HANDSHAKE_SERVER
            }
            TransparentMessage::PeerHandshake { .. } => {
                types::HANDSHAKE_PEER
            }
        }
    }
}

/// Message sent between the server and a client.
#[derive(Default, Debug)]
pub enum ServerMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Return an error message to the client.
    Error(StatusCode, String),
    /// Request a new meeting point.
    NewMeeting {
        /// The identifier for the owner of the meeting point.
        ///
        /// The owner id must exist in the set of slots.
        owner_id: UserId,
        /// Slots for participants in the meeting.
        slots: HashSet<UserId>,
        /// Data associated aith the meeting point.
        data: Value,
    },
    /// Response to a new meeting point request.
    MeetingCreated(MeetingState),
    /// Participant joins a meeting.
    JoinMeeting(MeetingId, UserId),
    /// Notification dispatched to all participants
    /// in a meeting when the limit for the meeting
    /// has been reached.
    MeetingReady(MeetingState),
    /// Request a new session.
    NewSession(SessionRequest),
    /// Register a peer connection in a session.
    SessionConnection {
        /// Session identifier.
        session_id: SessionId,
        /// Public key of the peer.
        peer_key: Vec<u8>,
    },
    /// Response to a new session request.
    SessionCreated(SessionState),
    /// Notification dispatched to all participants
    /// in a session when they have all completed
    /// the server handshake.
    SessionReady(SessionState),
    /// Notification dispatched to all participants
    /// in a session when they have all established
    /// peer connections to each other.
    SessionActive(SessionState),
    /// Notification dispatched to all participants
    /// in a session when the participants did not
    /// all connect within the expected timeframe.
    SessionTimeout(SessionId),
    /// Request to close a session.
    CloseSession(SessionId),
    /// Message sent when a session was closed.
    SessionFinished(SessionId),
}

impl From<&ServerMessage> for u8 {
    fn from(value: &ServerMessage) -> Self {
        match value {
            ServerMessage::Noop => types::NOOP,
            ServerMessage::Error(_, _) => types::ERROR,
            ServerMessage::NewMeeting { .. } => types::MEETING_NEW,
            ServerMessage::MeetingCreated(_) => {
                types::MEETING_CREATED
            }
            ServerMessage::JoinMeeting(_, _) => types::MEETING_JOIN,
            ServerMessage::MeetingReady(_) => types::MEETING_READY,
            ServerMessage::NewSession(_) => types::SESSION_NEW,
            ServerMessage::SessionConnection { .. } => {
                types::SESSION_CONNECTION
            }
            ServerMessage::SessionCreated(_) => {
                types::SESSION_CREATED
            }
            ServerMessage::SessionReady(_) => types::SESSION_READY,
            ServerMessage::SessionActive(_) => types::SESSION_ACTIVE,
            ServerMessage::SessionTimeout(_) => {
                types::SESSION_TIMEOUT
            }
            ServerMessage::CloseSession(_) => types::SESSION_CLOSE,
            ServerMessage::SessionFinished(_) => {
                types::SESSION_FINISHED
            }
        }
    }
}

/// Opaque messaages are encrypted.
#[derive(Default, Debug)]
pub enum OpaqueMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Encrypted message sent between the server and a client.
    ///
    /// After decrypting it can be decoded to a server message.
    ServerMessage(SealedEnvelope),

    /// Relay an encrypted message to a peer.
    PeerMessage {
        /// Public key of the receiver.
        public_key: Vec<u8>,
        /// Session identifier.
        session_id: Option<SessionId>,
        /// Message envelope.
        envelope: SealedEnvelope,
    },
}

impl From<&OpaqueMessage> for u8 {
    fn from(value: &OpaqueMessage) -> Self {
        match value {
            OpaqueMessage::Noop => types::NOOP,
            OpaqueMessage::ServerMessage(_) => types::OPAQUE_SERVER,
            OpaqueMessage::PeerMessage { .. } => types::OPAQUE_PEER,
        }
    }
}

/// Request message sent to the server or another peer.
#[derive(Default, Debug)]
pub enum RequestMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Transparent message used for the handshake(s).
    Transparent(TransparentMessage),

    /// Opaque encrypted messages.
    Opaque(OpaqueMessage),
}

impl From<&RequestMessage> for u8 {
    fn from(value: &RequestMessage) -> Self {
        match value {
            RequestMessage::Noop => types::NOOP,
            RequestMessage::Transparent(_) => types::TRANSPARENT,
            RequestMessage::Opaque(_) => types::OPAQUE,
        }
    }
}

/// Response message sent by the server or a peer.
#[derive(Default, Debug)]
pub enum ResponseMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Transparent message used for the handshake(s).
    Transparent(TransparentMessage),

    /// Opaque encrypted messages.
    Opaque(OpaqueMessage),
}

impl From<&ResponseMessage> for u8 {
    fn from(value: &ResponseMessage) -> Self {
        match value {
            ResponseMessage::Noop => types::NOOP,
            ResponseMessage::Transparent(_) => types::TRANSPARENT,
            ResponseMessage::Opaque(_) => types::OPAQUE,
        }
    }
}

/// Encoding for message payloads.
#[derive(Default, Clone, Copy, Debug)]
pub enum Encoding {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Binary encoding.
    Blob,
    /// JSON encoding.
    Json,
}

impl From<Encoding> for u8 {
    fn from(value: Encoding) -> Self {
        match value {
            Encoding::Noop => types::NOOP,
            Encoding::Blob => types::ENCODING_BLOB,
            Encoding::Json => types::ENCODING_JSON,
        }
    }
}

/// Chunk is used to respect the 65535 limit for
/// noise protocol messages.
///
/// Payloads may be larger than this limit so we chunk
/// them into individually encrypted payloads which then
/// need to be re-combined after each chunk has been decrypted.
#[derive(Default, Debug)]
pub struct Chunk {
    /// Length of the payload data.
    pub length: usize,
    /// Encrypted payload.
    pub contents: Vec<u8>,
}

impl Chunk {
    const CHUNK_SIZE: usize = 65535 - TAGLEN;

    /// Split a payload into encrypted chunks.
    pub fn split(
        payload: &[u8],
        transport: &mut TransportState,
    ) -> Result<Vec<Chunk>> {
        let mut chunks = Vec::new();
        for chunk in payload.chunks(Self::CHUNK_SIZE) {
            let mut contents = vec![0; chunk.len() + TAGLEN];
            let length =
                transport.write_message(chunk, &mut contents)?;
            chunks.push(Chunk { length, contents });
        }
        Ok(chunks)
    }

    /// Decrypt chunks and join into a single payload.
    pub fn join(
        chunks: Vec<Chunk>,
        transport: &mut TransportState,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        for chunk in chunks {
            let mut contents = vec![0; chunk.length];
            transport.read_message(
                &chunk.contents[..chunk.length],
                &mut contents,
            )?;
            let new_length = contents.len() - TAGLEN;
            contents.truncate(new_length);
            payload.extend_from_slice(contents.as_slice());
        }
        Ok(payload)
    }
}

/// Sealed envelope is an encrypted message.
///
/// The payload has been encrypted using the noise protocol
/// channel and the recipient must decrypt and decode the payload.
#[derive(Default, Debug)]
pub struct SealedEnvelope {
    /// Encoding for the payload.
    pub encoding: Encoding,
    /// Encrypted chunks.
    pub chunks: Vec<Chunk>,
    /// Whether this is a broadcast message.
    pub broadcast: bool,
}

/// Session is a namespace for a group of participants
/// to communicate for a series of rounds.
///
/// Use this for the keygen, signing or key refresh
/// of an MPC protocol.
pub struct Session {
    /// Public key of the owner.
    ///
    /// The owner is the initiator that created
    /// this session.
    owner_key: Vec<u8>,

    /// Public keys of the other session participants.
    participant_keys: HashSet<Vec<u8>>,

    /// Connections between peers established in this
    /// session context.
    connections: HashSet<(Vec<u8>, Vec<u8>)>,

    /// Last access time so the server can reap
    /// stale sessions.
    last_access: SystemTime,
}

impl Session {
    /// Public key of the session owner.
    pub fn owner_key(&self) -> &[u8] {
        self.owner_key.as_slice()
    }

    /// Get all participant's public keys
    pub fn public_keys(&self) -> Vec<&[u8]> {
        let mut keys = vec![self.owner_key.as_slice()];
        let mut participants: Vec<_> = self
            .participant_keys
            .iter()
            .map(|k| k.as_slice())
            .collect();
        keys.append(&mut participants);
        keys
    }

    /// Register a connection between peers.
    pub fn register_connection(
        &mut self,
        peer: Vec<u8>,
        other: Vec<u8>,
    ) {
        self.connections.insert((peer, other));
    }

    /// Determine if this session is active.
    ///
    /// A session is active when all participants have created
    /// their peer connections.
    pub fn is_active(&self) -> bool {
        let all_participants = self.public_keys();

        fn check_connection(
            connections: &HashSet<(Vec<u8>, Vec<u8>)>,
            peer: &[u8],
            all: &[&[u8]],
        ) -> bool {
            for key in all {
                if key == &peer {
                    continue;
                }
                // We don't know the order the connections
                // were established so check both.
                let left =
                    connections.get(&(peer.to_vec(), key.to_vec()));
                let right =
                    connections.get(&(key.to_vec(), peer.to_vec()));
                let is_connected = left.is_some() || right.is_some();
                if !is_connected {
                    return false;
                }
            }
            true
        }

        for key in &all_participants {
            let is_connected_others = check_connection(
                &self.connections,
                key,
                all_participants.as_slice(),
            );
            if !is_connected_others {
                return false;
            }
        }

        true
    }
}

/// Meeting point information.
#[derive(Debug)]
pub struct Meeting {
    /// Map of user identifiers to public keys.
    slots: HashMap<UserId, Option<Vec<u8>>>,

    /// Last access time so the server can reap
    /// stale meetings.
    last_access: SystemTime,

    /// Associated data for the meeting.
    data: Value,
}

impl Meeting {
    /// Add a participant public key to this meeting.
    pub fn join(&mut self, user_id: UserId, public_key: Vec<u8>) {
        self.slots.insert(user_id, Some(public_key));
        self.last_access = SystemTime::now();
    }

    /// Whether this meeting point is full.
    pub fn is_full(&self) -> bool {
        self.slots.values().all(|s| s.is_some())
    }

    /// Public keys of the meeting participants.
    pub fn participants(&self) -> Vec<Vec<u8>> {
        self.slots
            .values()
            .filter(|s| s.is_some())
            .map(|s| s.as_ref().unwrap().to_owned())
            .collect()
    }

    /// Associated data.
    pub fn data(&self) -> &Value {
        &self.data
    }
}

/// Manages a collection of meeting points.
#[derive(Default)]
pub struct MeetingManager {
    meetings: HashMap<MeetingId, Meeting>,
}

impl MeetingManager {
    /// Create a new meeting point.
    pub fn new_meeting(
        &mut self,
        owner_key: Vec<u8>,
        owner_id: UserId,
        slots: HashSet<UserId>,
        data: Value,
    ) -> MeetingId {
        let meeting_id = MeetingId::new_v4();
        let slots: HashMap<UserId, Option<Vec<u8>>> =
            slots.into_iter().map(|id| (id, None)).collect();

        let mut meeting = Meeting {
            slots,
            last_access: SystemTime::now(),
            data,
        };
        meeting.join(owner_id, owner_key);

        self.meetings.insert(meeting_id, meeting);
        meeting_id
    }

    /// Remove a meeting.
    pub fn remove_meeting(
        &mut self,
        id: &MeetingId,
    ) -> Option<Meeting> {
        self.meetings.remove(id)
    }

    /// Get a meeting.
    pub fn get_meeting(&self, id: &MeetingId) -> Option<&Meeting> {
        self.meetings.get(id)
    }

    /// Get a mutable meeting.
    pub fn get_meeting_mut(
        &mut self,
        id: &MeetingId,
    ) -> Option<&mut Meeting> {
        self.meetings.get_mut(id)
    }

    /// Get the keys of meetings that have expired.
    pub fn expired_keys(&self, timeout: u64) -> Vec<MeetingId> {
        self.meetings
            .iter()
            .filter(|(_, v)| {
                let now = SystemTime::now();
                let ttl = Duration::from_millis(timeout * 1000);
                if let Some(current) = v.last_access.checked_add(ttl)
                {
                    current < now
                } else {
                    false
                }
            })
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
    }
}

/// Manages a collection of sessions.
#[derive(Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
}

impl SessionManager {
    /// Create a new session.
    pub fn new_session(
        &mut self,
        owner_key: Vec<u8>,
        participant_keys: Vec<Vec<u8>>,
    ) -> SessionId {
        let session_id = SessionId::new_v4();
        let session = Session {
            owner_key,
            participant_keys: participant_keys.into_iter().collect(),
            connections: Default::default(),
            last_access: SystemTime::now(),
        };
        self.sessions.insert(session_id, session);
        session_id
    }

    /// Get a session.
    pub fn get_session(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Get a mutable session.
    pub fn get_session_mut(
        &mut self,
        id: &SessionId,
    ) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Remove a session.
    pub fn remove_session(
        &mut self,
        id: &SessionId,
    ) -> Option<Session> {
        self.sessions.remove(id)
    }

    /// Retrieve and update the last access time for a session.
    pub fn touch_session(
        &mut self,
        id: &SessionId,
    ) -> Option<&Session> {
        if let Some(session) = self.sessions.get_mut(id) {
            session.last_access = SystemTime::now();
            Some(&*session)
        } else {
            None
        }
    }

    /// Get the keys of sessions that have expired.
    pub fn expired_keys(&self, timeout: u64) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|(_, v)| {
                let now = SystemTime::now();
                let ttl = Duration::from_millis(timeout * 1000);
                if let Some(current) = v.last_access.checked_add(ttl)
                {
                    current < now
                } else {
                    false
                }
            })
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
    }
}

/// Response from creating a meeting point.
#[derive(Default, Debug, Clone)]
pub struct MeetingState {
    /// Meeting identifier.
    pub meeting_id: MeetingId,
    /// Public keys of the registered participants.
    pub registered_participants: Vec<Vec<u8>>,
    /// Data for the meeting state.
    pub data: Value,
}

/// Request to create a new session.
///
/// Do no include the public key of the initiator as it
/// is automatically added as the session *owner*.
#[derive(Default, Debug)]
pub struct SessionRequest {
    /// Public keys of the session participants.
    pub participant_keys: Vec<Vec<u8>>,
}

/// Response from creating new session.
#[derive(Default, Debug, Clone)]
pub struct SessionState {
    /// Session identifier.
    pub session_id: SessionId,
    /// Public keys of all participants.
    pub all_participants: Vec<Vec<u8>>,
}

impl SessionState {
    /// Total number of participants in this session.
    pub fn len(&self) -> usize {
        self.all_participants.len()
    }

    /// Get the party index from a public key.
    pub fn party_number(
        &self,
        public_key: impl AsRef<[u8]>,
    ) -> Option<PartyNumber> {
        self.all_participants
            .iter()
            .position(|k| k == public_key.as_ref())
            .map(|pos| PartyNumber::new((pos + 1) as u16).unwrap())
    }

    /// Get the public key for a party number.
    pub fn peer_key(
        &self,
        party_number: PartyNumber,
    ) -> Option<&[u8]> {
        for (index, key) in self.all_participants.iter().enumerate() {
            if index + 1 == party_number.get() as usize {
                return Some(key.as_slice());
            }
        }
        None
    }

    /// Get the connections a peer should make.
    pub fn connections(&self, own_key: &[u8]) -> &[Vec<u8>] {
        if self.all_participants.is_empty() {
            return &[];
        }

        if let Some(position) =
            self.all_participants.iter().position(|k| k == own_key)
        {
            if position < self.all_participants.len() - 1 {
                &self.all_participants[position + 1..]
            } else {
                &[]
            }
        } else {
            &[]
        }
    }

    /// Get the recipients for a broadcast message.
    pub fn recipients(&self, own_key: &[u8]) -> Vec<Vec<u8>> {
        self.all_participants
            .iter()
            .filter(|&k| k != own_key)
            .map(|k| k.to_vec())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Chunk;
    use crate::PATTERN;
    use anyhow::Result;

    #[test]
    fn chunks_split_join() -> Result<()> {
        let builder_1 = snow::Builder::new(PATTERN.parse()?);
        let builder_2 = snow::Builder::new(PATTERN.parse()?);

        let keypair1 = builder_1.generate_keypair()?;
        let keypair2 = builder_2.generate_keypair()?;

        let mut initiator = builder_1
            .local_private_key(&keypair1.private)
            .remote_public_key(&keypair2.public)
            .build_initiator()?;

        let mut responder = builder_2
            .local_private_key(&keypair2.private)
            .remote_public_key(&keypair1.public)
            .build_responder()?;

        let (mut read_buf, mut first_msg, mut second_msg) =
            ([0u8; 1024], [0u8; 1024], [0u8; 1024]);

        // -> e
        let len = initiator.write_message(&[], &mut first_msg)?;

        // responder processes the first message...
        responder.read_message(&first_msg[..len], &mut read_buf)?;

        // <- e, ee
        let len = responder.write_message(&[], &mut second_msg)?;

        // initiator processes the response...
        initiator.read_message(&second_msg[..len], &mut read_buf)?;

        // NN handshake complete, transition into transport mode.
        let mut initiator = initiator.into_transport_mode()?;
        let mut responder = responder.into_transport_mode()?;

        let mock_payload = vec![0; 76893];

        // Split into chunks
        let chunks = Chunk::split(&mock_payload, &mut initiator)?;
        assert_eq!(2, chunks.len());

        // Decrypt and combine the chunks
        let decrypted_payload = Chunk::join(chunks, &mut responder)?;
        assert_eq!(mock_payload, decrypted_payload);

        Ok(())
    }
}
