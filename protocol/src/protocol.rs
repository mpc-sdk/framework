use async_trait::async_trait;
use binary_stream::{
    futures::{BinaryReader, BinaryWriter, Decodable, Encodable},
    Endian, Options,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use http::StatusCode;
use snow::{HandshakeState, TransportState};
use std::{
    collections::{HashMap, HashSet},
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

    pub const HANDSHAKE_MSG_INITIATOR: u8 = 1;
    pub const HANDSHAKE_MSG_RESPONDER: u8 = 2;

    pub const HANDSHAKE_SERVER: u8 = 1;
    pub const HANDSHAKE_PEER: u8 = 2;

    pub const TRANSPARENT: u8 = 128;
    pub const OPAQUE: u8 = 129;

    pub const PEER_REQUEST: u8 = 1;
    pub const PEER_RESPONSE: u8 = 2;

    pub const NOOP: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const HANDSHAKE_INITIATOR: u8 = 2;
    pub const HANDSHAKE_RESPONDER: u8 = 3;
    pub const RELAY_PEER: u8 = 4;
    pub const ENVELOPE: u8 = 5;
    pub const SESSION_NEW: u8 = 6;
    pub const SESSION_CREATED: u8 = 7;
    pub const SESSION_READY_NOTIFY: u8 = 8;
    pub const SESSION_READY: u8 = 9;
    pub const SESSION_CONNECTION: u8 = 10;
    pub const SESSION_ACTIVE_NOTIFY: u8 = 11;
    pub const SESSION_ACTIVE: u8 = 12;

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

/// Identifier for sessions.
pub type SessionId = uuid::Uuid;

/// Encode to a binary buffer.
pub async fn encode(encodable: &impl Encodable) -> Result<Vec<u8>> {
    binary_stream::futures::encode(encodable, encoding_options())
        .await
}

/// Decode from a binary buffer.
pub async fn decode<T: Decodable + Default>(
    buffer: impl AsRef<[u8]>,
) -> Result<T> {
    binary_stream::futures::decode(
        buffer.as_ref(),
        encoding_options(),
    )
    .await
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
    Handshake(Box<HandshakeState>),
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
                types::HANDSHAKE_MSG_INITIATOR
            }
            HandshakeMessage::Responder(_, _) => {
                types::HANDSHAKE_MSG_RESPONDER
            }
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for HandshakeMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::Initiator(len, buf) => {
                writer.write_usize(len).await?;
                writer.write_u32(buf.len() as u32).await?;
                writer.write_bytes(buf).await?;
            }
            Self::Responder(len, buf) => {
                writer.write_usize(len).await?;
                writer.write_u32(buf.len() as u32).await?;
                writer.write_bytes(buf).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for HandshakeMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::HANDSHAKE_MSG_INITIATOR => {
                let len = reader.read_usize().await?;
                let size = reader.read_u32().await?;
                let buf = reader.read_bytes(size as usize).await?;
                *self = HandshakeMessage::Initiator(len, buf);
            }
            types::HANDSHAKE_MSG_RESPONDER => {
                let len = reader.read_usize().await?;
                let size = reader.read_u32().await?;
                let buf = reader.read_bytes(size as usize).await?;
                *self = HandshakeMessage::Responder(len, buf);
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

/// Transparent messaages are not encrypted.
#[derive(Default, Debug)]
pub enum TransparentMessage {
    #[default]
    #[doc(hidden)]
    Noop,
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
            TransparentMessage::ServerHandshake(_) => {
                types::HANDSHAKE_SERVER
            }
            TransparentMessage::PeerHandshake { .. } => {
                types::HANDSHAKE_PEER
            }
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for TransparentMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::ServerHandshake(message) => {
                message.encode(writer).await?;
            }
            Self::PeerHandshake {
                public_key,
                message,
            } => {
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                message.encode(writer).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for TransparentMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::HANDSHAKE_SERVER => {
                let mut message: HandshakeMessage =
                    Default::default();
                message.decode(reader).await?;
                *self = TransparentMessage::ServerHandshake(message);
            }
            types::HANDSHAKE_PEER => {
                let size = reader.read_u32().await?;
                let public_key =
                    reader.read_bytes(size as usize).await?;
                let mut message: HandshakeMessage =
                    Default::default();
                message.decode(reader).await?;
                *self = TransparentMessage::PeerHandshake {
                    public_key,
                    message,
                };
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

/// Opaque messaages are encrypted.
#[derive(Default, Debug)]
pub enum Opaque {
    #[default]
    #[doc(hidden)]
    Noop,
    // TODO
}

/// Request message sent to the server or another peer.
#[derive(Default, Debug)]
pub enum RequestMessage {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Transparent message used for the handshake(s).
    Transparent(TransparentMessage),

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
        /// Session identifier.
        session_id: Option<SessionId>,
    },
    /// Envelope for an encrypted message over the server channel.
    Envelope(Vec<u8>),
    /// Request a new session.
    NewSession(SessionRequest),
    /// Request to notify all participants when the
    /// session is ready.
    SessionReadyNotify(SessionId),
    /// Register a peer connection in a session.
    SessionConnection {
        /// Session identifier.
        session_id: SessionId,
        /// Public key of the peer.
        peer_key: Vec<u8>,
    },
    /// Request to notify all participants when the
    /// session is active.
    SessionActiveNotify(SessionId),
}

impl From<&RequestMessage> for u8 {
    fn from(value: &RequestMessage) -> Self {
        match value {
            RequestMessage::Noop => types::NOOP,
            RequestMessage::Transparent(_) => types::TRANSPARENT,
            RequestMessage::HandshakeInitiator(_, _, _) => {
                types::HANDSHAKE_INITIATOR
            }
            RequestMessage::RelayPeer { .. } => types::RELAY_PEER,
            RequestMessage::Envelope(_) => types::ENVELOPE,
            RequestMessage::NewSession(_) => types::SESSION_NEW,
            RequestMessage::SessionReadyNotify(_) => {
                types::SESSION_READY_NOTIFY
            }
            RequestMessage::SessionConnection { .. } => {
                types::SESSION_CONNECTION
            }
            RequestMessage::SessionActiveNotify(_) => {
                types::SESSION_ACTIVE_NOTIFY
            }
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
            Self::Transparent(message) => {
                message.encode(writer).await?;
            }
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
                session_id,
            } => {
                writer.write_bool(handshake).await?;
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
                writer.write_bool(session_id.is_some()).await?;
                if let Some(id) = session_id {
                    writer.write_bytes(id.as_bytes()).await?;
                }
            }
            Self::Envelope(message) => {
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
            }
            Self::NewSession(request) => {
                request.encode(writer).await?;
            }
            Self::SessionReadyNotify(session_id) => {
                writer.write_bytes(session_id.as_bytes()).await?;
            }
            Self::SessionConnection {
                session_id,
                peer_key,
            } => {
                writer.write_bytes(session_id.as_bytes()).await?;
                writer.write_u32(peer_key.len() as u32).await?;
                writer.write_bytes(peer_key).await?;
            }
            Self::SessionActiveNotify(session_id) => {
                writer.write_bytes(session_id.as_bytes()).await?;
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
            types::TRANSPARENT => {
                let mut message: TransparentMessage =
                    Default::default();
                message.decode(reader).await?;
                *self = RequestMessage::Transparent(message);
            }
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
                let has_session_id = reader.read_bool().await?;

                let session_id = if has_session_id {
                    let session_id = SessionId::from_bytes(
                        reader
                            .read_bytes(16)
                            .await?
                            .as_slice()
                            .try_into()
                            .map_err(encoding_error)?,
                    );
                    Some(session_id)
                } else {
                    None
                };

                *self = RequestMessage::RelayPeer {
                    handshake,
                    public_key,
                    message,
                    session_id,
                };
            }
            types::ENVELOPE => {
                let size = reader.read_u32().await?;
                let message =
                    reader.read_bytes(size as usize).await?;
                *self = RequestMessage::Envelope(message);
            }
            types::SESSION_NEW => {
                let mut session: SessionRequest = Default::default();
                session.decode(reader).await?;
                *self = RequestMessage::NewSession(session);
            }
            types::SESSION_READY_NOTIFY => {
                let session_id = SessionId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                *self =
                    RequestMessage::SessionReadyNotify(session_id);
            }
            types::SESSION_CONNECTION => {
                let session_id = SessionId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );

                let size = reader.read_u32().await?;
                let peer_key =
                    reader.read_bytes(size as usize).await?;

                *self = RequestMessage::SessionConnection {
                    session_id,
                    peer_key,
                };
            }
            types::SESSION_ACTIVE_NOTIFY => {
                let session_id = SessionId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                *self =
                    RequestMessage::SessionActiveNotify(session_id);
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

/// Response message sent by the server or a peer.
#[derive(Default, Debug)]
pub enum ResponseMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Return an error message to the client.
    Error(StatusCode, String),

    /// Transparent message used for the handshake(s).
    Transparent(TransparentMessage),

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
    SessionCreated(SessionState),
    /// Notification dispatched to all participants
    /// in a session when they have all completed
    /// the server handshake.
    SessionReady(SessionState),
    /// Notification dispatched to all participants
    /// in a session when they have all established
    /// peer connections to each other.
    SessionActive(SessionState),
}

impl From<&ResponseMessage> for u8 {
    fn from(value: &ResponseMessage) -> Self {
        match value {
            ResponseMessage::Noop => types::NOOP,
            ResponseMessage::Error(_, _) => types::ERROR,
            ResponseMessage::Transparent(_) => types::TRANSPARENT,
            ResponseMessage::HandshakeResponder(_, _, _) => {
                types::HANDSHAKE_RESPONDER
            }
            ResponseMessage::RelayPeer { .. } => types::RELAY_PEER,
            ResponseMessage::Envelope(_) => types::ENVELOPE,
            ResponseMessage::SessionCreated(_) => {
                types::SESSION_CREATED
            }
            ResponseMessage::SessionReady(_) => types::SESSION_READY,
            ResponseMessage::SessionActive(_) => {
                types::SESSION_ACTIVE
            }
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
            Self::Transparent(message) => {
                message.encode(&mut *writer).await?;
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
            Self::SessionCreated(response) => {
                response.encode(writer).await?;
            }
            Self::SessionReady(response) => {
                response.encode(writer).await?;
            }
            Self::SessionActive(response) => {
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
            types::TRANSPARENT => {
                let mut message: TransparentMessage =
                    Default::default();
                message.decode(reader).await?;
                *self = ResponseMessage::Transparent(message);
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
            types::SESSION_CREATED => {
                let mut session: SessionState = Default::default();
                session.decode(reader).await?;
                *self = ResponseMessage::SessionCreated(session);
            }
            types::SESSION_READY => {
                let mut session: SessionState = Default::default();
                session.decode(reader).await?;
                *self = ResponseMessage::SessionReady(session);
            }
            types::SESSION_ACTIVE => {
                let mut session: SessionState = Default::default();
                session.decode(reader).await?;
                *self = ResponseMessage::SessionActive(session);
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

/// Sealed envelope is an encrypted message.
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
    /// Whether this is a broadcast message.
    pub broadcast: bool,
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
        writer.write_bool(self.broadcast).await?;
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
        self.broadcast = reader.read_bool().await?;
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
    participant_keys: HashSet<Vec<u8>>,

    /// Connections between peers established in this
    /// session context.
    connections: HashSet<(Vec<u8>, Vec<u8>)>,

    /// Last access time so the server can reap
    /// stale sessions.
    last_access: SystemTime,
}

impl Session {
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

/// Request to create a new session.
///
/// Do no include the public key of the initiator as it
/// is automatically added as the session *owner*.
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
#[derive(Default, Debug, Clone)]
pub struct SessionState {
    /// Session identifier.
    pub session_id: SessionId,
    /// Public keys of all participants.
    pub all_participants: Vec<Vec<u8>>,
}

impl SessionState {
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
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for SessionState {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.session_id.as_bytes()).await?;
        writer.write_u32(self.all_participants.len() as u32).await?;
        for conn in &self.all_participants {
            writer.write_u32(conn.len() as u32).await?;
            writer.write_bytes(conn).await?;
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for SessionState {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.session_id = SessionId::from_bytes(
            reader
                .read_bytes(16)
                .await?
                .as_slice()
                .try_into()
                .map_err(encoding_error)?,
        );
        let size = reader.read_u32().await?;
        for _ in 0..size {
            let len = reader.read_u32().await?;
            self.all_participants
                .push(reader.read_bytes(len as usize).await?);
        }
        Ok(())
    }
}
