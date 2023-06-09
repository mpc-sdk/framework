use async_trait::async_trait;
use binary_stream::{
    futures::{BinaryReader, BinaryWriter, Decodable, Encodable},
    Endian, Options,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use http::StatusCode;
use snow::{HandshakeState, TransportState};
use std::{
    collections::HashMap,
    io::Result,
    time::{Duration, SystemTime},
};

pub(crate) fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

mod types {
    pub const HANDSHAKE_TYPE_SERVER: u8 = 1;
    pub const HANDSHAKE_TYPE_PEER: u8 = 2;

    pub const PEER_REQUEST: u8 = 1;
    pub const PEER_RESPONSE: u8 = 2;

    pub const NOOP: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const HANDSHAKE_INITIATOR: u8 = 2;
    pub const HANDSHAKE_RESPONDER: u8 = 3;
    pub const RELAY_PEER: u8 = 4;
    pub const ENVELOPE: u8 = 5;
    pub const SESSION: u8 = 6;

    pub const ENCODING_BLOB: u8 = 1;
    pub const ENCODING_JSON: u8 = 2;
}

/// Default binary encoding options.
fn encoding_options() -> Options {
    Options {
        endian: Endian::Little,
        max_buffer_size: Some(1024 * 32),
    }
}

type SessionId = uuid::Uuid;

/// Encode to a binary buffer.
pub async fn encode(encodable: &impl Encodable) -> Result<Vec<u8>> {
    Ok(
        binary_stream::futures::encode(encodable, encoding_options())
            .await?,
    )
}

/// Decode from a binary buffer.
pub async fn decode<T: Decodable + Default>(
    buffer: impl AsRef<[u8]>,
) -> Result<T> {
    Ok(binary_stream::futures::decode(
        buffer.as_ref(),
        encoding_options(),
    )
    .await?)
}

/// Types of noise protocol handshakes.
#[derive(Debug, Default)]
pub enum HandshakeType {
    /// Server handshake.
    #[default]
    Server,
    /// Peer handshake.
    Peer,
}

impl From<&HandshakeType> for u8 {
    fn from(value: &HandshakeType) -> Self {
        match value {
            HandshakeType::Server => types::HANDSHAKE_TYPE_SERVER,
            HandshakeType::Peer => types::HANDSHAKE_TYPE_PEER,
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for HandshakeType {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for HandshakeType {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::HANDSHAKE_TYPE_SERVER => {
                *self = HandshakeType::Server;
            }
            types::HANDSHAKE_TYPE_PEER => {
                *self = HandshakeType::Peer;
            }
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        Ok(())
    }
}

/// Enumeration of protocol states.
pub enum ProtocolState {
    /// Noise handshake state.
    Handshake(HandshakeState),
    /// Noise transport state.
    Transport(TransportState),
}

/// Wrappper for messages sent between peers.
#[derive(Default)]
pub enum PeerMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Request message.
    Request(RequestMessage),
    /// Response message.
    Response(ResponseMessage),
}

impl From<&PeerMessage> for u8 {
    fn from(value: &PeerMessage) -> Self {
        match value {
            PeerMessage::Noop => types::NOOP,
            PeerMessage::Request(_) => types::PEER_REQUEST,
            PeerMessage::Response(_) => types::PEER_RESPONSE,
        }
    }
}

impl From<RequestMessage> for PeerMessage {
    fn from(value: RequestMessage) -> Self {
        Self::Request(value)
    }
}

impl From<ResponseMessage> for PeerMessage {
    fn from(value: ResponseMessage) -> Self {
        Self::Response(value)
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for PeerMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::Request(message) => {
                message.encode(writer).await?;
            }
            Self::Response(message) => {
                message.encode(writer).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for PeerMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::PEER_REQUEST => {
                let mut message: RequestMessage = Default::default();
                message.decode(reader).await?;
                *self = PeerMessage::Request(message)
            }
            types::PEER_RESPONSE => {
                let mut message: ResponseMessage = Default::default();
                message.decode(reader).await?;
                *self = PeerMessage::Response(message)
            }
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        Ok(())
    }
}

/// Request messages from the client.
#[derive(Default, Debug)]
pub enum RequestMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Initiate a handshake.
    HandshakeInitiator(HandshakeType, usize, Vec<u8>),
    /// Relay a message to a peer.
    RelayPeer {
        /// Determines if this message is part of the
        /// peer to peer handshake.
        handshake: bool,
        /// Public key of the receiver.
        public_key: Vec<u8>,
        /// Message payload.
        message: Vec<u8>,
    },
    /// Envelope for an encrypted message over the server channel.
    Envelope(Vec<u8>),
    /// Request a new session.
    Session(SessionRequest),
}

impl From<&RequestMessage> for u8 {
    fn from(value: &RequestMessage) -> Self {
        match value {
            RequestMessage::Noop => types::NOOP,
            RequestMessage::HandshakeInitiator(_, _, _) => {
                types::HANDSHAKE_INITIATOR
            }
            RequestMessage::RelayPeer { .. } => types::RELAY_PEER,
            RequestMessage::Envelope(_) => types::ENVELOPE,
            RequestMessage::Session(_) => types::SESSION,
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for RequestMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::HandshakeInitiator(kind, len, buf) => {
                kind.encode(&mut *writer).await?;
                writer.write_usize(len).await?;
                writer.write_u32(buf.len() as u32).await?;
                writer.write_bytes(buf).await?;
            }
            Self::RelayPeer {
                handshake,
                public_key,
                message,
            } => {
                writer.write_bool(handshake).await?;
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
            }
            Self::Envelope(message) => {
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
            }
            Self::Session(request) => {
                request.encode(writer).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for RequestMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::HANDSHAKE_INITIATOR => {
                let mut kind: HandshakeType = Default::default();
                kind.decode(&mut *reader).await?;
                let len = reader.read_usize().await?;
                let size = reader.read_u32().await?;
                let buf = reader.read_bytes(size as usize).await?;
                *self = RequestMessage::HandshakeInitiator(
                    kind, len, buf,
                );
            }
            types::RELAY_PEER => {
                let handshake = reader.read_bool().await?;
                let size = reader.read_u32().await?;
                let public_key =
                    reader.read_bytes(size as usize).await?;
                let size = reader.read_u32().await?;
                let message =
                    reader.read_bytes(size as usize).await?;
                *self = RequestMessage::RelayPeer {
                    handshake,
                    public_key,
                    message,
                };
            }
            types::ENVELOPE => {
                let size = reader.read_u32().await?;
                let message =
                    reader.read_bytes(size as usize).await?;
                *self = RequestMessage::Envelope(message);
            }
            types::SESSION => {
                let mut session: SessionRequest = Default::default();
                session.decode(reader).await?;
                *self = RequestMessage::Session(session);
            }
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        Ok(())
    }
}

/// Response messages from the server.
#[derive(Default, Debug)]
pub enum ResponseMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Return an error message to the client.
    Error(StatusCode, String),
    /// Respond to a handshake initiation.
    HandshakeResponder(HandshakeType, usize, Vec<u8>),
    /// Message being relayed from another peer.
    RelayPeer {
        /// Determines if this message is part of the
        /// peer to peer handshake.
        handshake: bool,
        /// Public key of the sender.
        public_key: Vec<u8>,
        /// Message payload.
        message: Vec<u8>,
    },
    /// Envelope for an encrypted message over the server channel.
    Envelope(Vec<u8>),
    /// Response to a new session request.
    Session(SessionResponse),
}

impl From<&ResponseMessage> for u8 {
    fn from(value: &ResponseMessage) -> Self {
        match value {
            ResponseMessage::Noop => types::NOOP,
            ResponseMessage::Error(_, _) => types::ERROR,
            ResponseMessage::HandshakeResponder(_, _, _) => {
                types::HANDSHAKE_RESPONDER
            }
            ResponseMessage::RelayPeer { .. } => types::RELAY_PEER,
            ResponseMessage::Envelope(_) => types::ENVELOPE,
            ResponseMessage::Session(_) => types::SESSION,
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for ResponseMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::Error(code, message) => {
                let code: u16 = (*code).into();
                writer.write_u16(code).await?;
                writer.write_string(message).await?;
            }
            Self::HandshakeResponder(kind, len, buf) => {
                kind.encode(&mut *writer).await?;
                writer.write_usize(len).await?;
                writer.write_u32(buf.len() as u32).await?;
                writer.write_bytes(buf).await?;
            }
            Self::RelayPeer {
                handshake,
                public_key,
                message,
            } => {
                writer.write_bool(handshake).await?;
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
            }
            Self::Envelope(message) => {
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
            }
            Self::Session(response) => {
                response.encode(writer).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for ResponseMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::ERROR => {
                let code = reader
                    .read_u16()
                    .await?
                    .try_into()
                    .map_err(encoding_error)?;
                let message = reader.read_string().await?;
                *self = ResponseMessage::Error(code, message);
            }
            types::HANDSHAKE_RESPONDER => {
                let mut kind: HandshakeType = Default::default();
                kind.decode(&mut *reader).await?;
                let len = reader.read_usize().await?;
                let size = reader.read_u32().await?;
                let buf = reader.read_bytes(size as usize).await?;
                *self = ResponseMessage::HandshakeResponder(
                    kind, len, buf,
                );
            }
            types::RELAY_PEER => {
                let handshake = reader.read_bool().await?;
                let size = reader.read_u32().await?;
                let public_key =
                    reader.read_bytes(size as usize).await?;
                let size = reader.read_u32().await?;
                let message =
                    reader.read_bytes(size as usize).await?;
                *self = ResponseMessage::RelayPeer {
                    handshake,
                    public_key,
                    message,
                };
            }
            types::ENVELOPE => {
                let size = reader.read_u32().await?;
                let message =
                    reader.read_bytes(size as usize).await?;
                *self = ResponseMessage::Envelope(message);
            }
            types::SESSION => {
                let mut session: SessionResponse = Default::default();
                session.decode(reader).await?;
                *self = ResponseMessage::Session(session);
            }
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        Ok(())
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

/// Sealed message sent between peers.
///
/// The payload has been encrypted using the noise protocol
/// channel and the recipient must decrypt and decode the payload.
#[derive(Default, Debug)]
pub struct SealedEnvelope {
    /// Encoding for the payload.
    pub encoding: Encoding,
    /// Length of the payload data.
    pub length: usize,
    /// Encrypted payload.
    pub payload: Vec<u8>,
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for SealedEnvelope {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.encoding.into();
        writer.write_u8(id).await?;
        writer.write_usize(self.length).await?;
        writer.write_u32(self.payload.len() as u32).await?;
        writer.write_bytes(&self.payload).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for SealedEnvelope {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::ENCODING_BLOB => {
                self.encoding = Encoding::Blob;
            }
            types::ENCODING_JSON => {
                self.encoding = Encoding::Json;
            }
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        self.length = reader.read_usize().await?;
        let size = reader.read_u32().await?;
        self.payload = reader.read_bytes(size as usize).await?;
        Ok(())
    }
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
    participant_keys: Vec<Vec<u8>>,

    /// Last access time so the server can reap
    /// stale sessions.
    last_access: SystemTime,
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
            participant_keys,
            last_access: SystemTime::now(),
        };
        self.sessions.insert(session_id.clone(), session);
        session_id
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

/// Request to create a new session.
#[derive(Default, Debug)]
pub struct SessionRequest {
    /// Public keys of the session participants.
    pub participant_keys: Vec<Vec<u8>>,
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for SessionRequest {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // TODO: handle too many participants
        writer.write_u32(self.participant_keys.len() as u32).await?;
        for key in self.participant_keys.iter() {
            writer.write_u32(key.len() as u32).await?;
            writer.write_bytes(key).await?;
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for SessionRequest {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let size = reader.read_u32().await? as usize;
        for _ in 0..size {
            let len = reader.read_u32().await? as usize;
            let key = reader.read_bytes(len).await?;
            self.participant_keys.push(key);
        }
        Ok(())
    }
}

/// Response from creating new session.
#[derive(Default, Debug)]
pub struct SessionResponse {
    /// Session identifier.
    pub id: String,
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for SessionResponse {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_string(&self.id).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for SessionResponse {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.id = reader.read_string().await?;
        Ok(())
    }
}
