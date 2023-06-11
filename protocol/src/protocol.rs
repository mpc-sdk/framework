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
    pub const HANDSHAKE_INITIATOR: u8 = 1;
    pub const HANDSHAKE_RESPONDER: u8 = 2;

    pub const HANDSHAKE_SERVER: u8 = 1;
    pub const HANDSHAKE_PEER: u8 = 2;

    pub const TRANSPARENT: u8 = 128;
    pub const OPAQUE: u8 = 129;

    pub const OPAQUE_SERVER: u8 = 1;
    pub const OPAQUE_PEER: u8 = 2;

    pub const NOOP: u8 = 0;
    pub const RELAY_PEER: u8 = 2;

    pub const SESSION_NEW: u8 = 1;
    pub const SESSION_CREATED: u8 = 2;
    pub const SESSION_READY_NOTIFY: u8 = 3;
    pub const SESSION_READY: u8 = 4;
    pub const SESSION_CONNECTION: u8 = 5;
    pub const SESSION_ACTIVE_NOTIFY: u8 = 6;
    pub const SESSION_ACTIVE: u8 = 7;

    pub const ENCODING_BLOB: u8 = 1;
    pub const ENCODING_JSON: u8 = 2;

    pub const ERROR: u8 = 255;
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
            types::HANDSHAKE_INITIATOR => {
                let len = reader.read_usize().await?;
                let size = reader.read_u32().await?;
                let buf = reader.read_bytes(size as usize).await?;
                *self = HandshakeMessage::Initiator(len, buf);
            }
            types::HANDSHAKE_RESPONDER => {
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

/// Message sent between the server and a client.
#[derive(Default, Debug)]
pub enum ServerMessage {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Return an error message to the client.
    Error(StatusCode, String),
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

impl From<&ServerMessage> for u8 {
    fn from(value: &ServerMessage) -> Self {
        match value {
            ServerMessage::Noop => types::NOOP,
            ServerMessage::Error(_, _) => types::ERROR,
            ServerMessage::NewSession(_) => types::SESSION_NEW,
            ServerMessage::SessionReadyNotify(_) => {
                types::SESSION_READY_NOTIFY
            }
            ServerMessage::SessionConnection { .. } => {
                types::SESSION_CONNECTION
            }
            ServerMessage::SessionActiveNotify(_) => {
                types::SESSION_ACTIVE_NOTIFY
            }
            ServerMessage::SessionCreated(_) => {
                types::SESSION_CREATED
            }
            ServerMessage::SessionReady(_) => types::SESSION_READY,
            ServerMessage::SessionActive(_) => types::SESSION_ACTIVE,
        }
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for ServerMessage {
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
impl Decodable for ServerMessage {
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
                *self = ServerMessage::Error(code, message);
            }
            types::SESSION_NEW => {
                let mut session: SessionRequest = Default::default();
                session.decode(reader).await?;
                *self = ServerMessage::NewSession(session);
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
                *self = ServerMessage::SessionReadyNotify(session_id);
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

                *self = ServerMessage::SessionConnection {
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
                    ServerMessage::SessionActiveNotify(session_id);
            }
            types::SESSION_CREATED => {
                let mut session: SessionState = Default::default();
                session.decode(reader).await?;
                *self = ServerMessage::SessionCreated(session);
            }
            types::SESSION_READY => {
                let mut session: SessionState = Default::default();
                session.decode(reader).await?;
                *self = ServerMessage::SessionReady(session);
            }
            types::SESSION_ACTIVE => {
                let mut session: SessionState = Default::default();
                session.decode(reader).await?;
                *self = ServerMessage::SessionActive(session);
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for OpaqueMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::ServerMessage(envelope) => {
                envelope.encode(writer).await?;
            }
            Self::PeerMessage {
                public_key,
                session_id,
                envelope,
            } => {
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                writer.write_bool(session_id.is_some()).await?;
                if let Some(id) = session_id {
                    writer.write_bytes(id.as_bytes()).await?;
                }
                envelope.encode(writer).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for OpaqueMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::OPAQUE_SERVER => {
                let mut envelope: SealedEnvelope = Default::default();
                envelope.decode(reader).await?;
                *self = OpaqueMessage::ServerMessage(envelope);
            }
            types::OPAQUE_PEER => {
                let size = reader.read_u32().await?;
                let public_key =
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

                let mut envelope: SealedEnvelope = Default::default();
                envelope.decode(reader).await?;

                *self = OpaqueMessage::PeerMessage {
                    public_key,
                    session_id,
                    envelope,
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

    /// Relay a message to a peer.
    RelayPeer {
        /// Public key of the receiver.
        public_key: Vec<u8>,
        /// Message payload.
        message: Vec<u8>,
        /// Session identifier.
        session_id: Option<SessionId>,
    },
}

impl From<&RequestMessage> for u8 {
    fn from(value: &RequestMessage) -> Self {
        match value {
            RequestMessage::Noop => types::NOOP,
            RequestMessage::Transparent(_) => types::TRANSPARENT,
            RequestMessage::Opaque(_) => types::OPAQUE,
            RequestMessage::RelayPeer { .. } => types::RELAY_PEER,
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
            Self::Opaque(message) => {
                message.encode(writer).await?;
            }
            Self::RelayPeer {
                public_key,
                message,
                session_id,
            } => {
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
                writer.write_bool(session_id.is_some()).await?;
                if let Some(id) = session_id {
                    writer.write_bytes(id.as_bytes()).await?;
                }
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
            types::OPAQUE => {
                let mut message: OpaqueMessage = Default::default();
                message.decode(reader).await?;
                *self = RequestMessage::Opaque(message);
            }
            types::RELAY_PEER => {
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
                    public_key,
                    message,
                    session_id,
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

    /// Message being relayed from another peer.
    RelayPeer {
        /// Public key of the sender.
        public_key: Vec<u8>,
        /// Message payload.
        message: Vec<u8>,
    },
}

impl From<&ResponseMessage> for u8 {
    fn from(value: &ResponseMessage) -> Self {
        match value {
            ResponseMessage::Noop => types::NOOP,
            ResponseMessage::Transparent(_) => types::TRANSPARENT,
            ResponseMessage::Opaque(_) => types::OPAQUE,

            ResponseMessage::RelayPeer { .. } => types::RELAY_PEER,
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
            Self::Transparent(message) => {
                message.encode(&mut *writer).await?;
            }
            Self::Opaque(message) => {
                message.encode(&mut *writer).await?;
            }
            Self::RelayPeer {
                public_key,
                message,
            } => {
                writer.write_u32(public_key.len() as u32).await?;
                writer.write_bytes(public_key).await?;
                writer.write_u32(message.len() as u32).await?;
                writer.write_bytes(message).await?;
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
            types::TRANSPARENT => {
                let mut message: TransparentMessage =
                    Default::default();
                message.decode(reader).await?;
                *self = ResponseMessage::Transparent(message);
            }
            types::OPAQUE => {
                let mut message: OpaqueMessage = Default::default();
                message.decode(reader).await?;
                *self = ResponseMessage::Opaque(message);
            }
            types::RELAY_PEER => {
                let size = reader.read_u32().await?;
                let public_key =
                    reader.read_bytes(size as usize).await?;
                let size = reader.read_u32().await?;
                let message =
                    reader.read_bytes(size as usize).await?;
                *self = ResponseMessage::RelayPeer {
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
