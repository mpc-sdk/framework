use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

use crate::{
    encoding::{encoding_error, types},
    Encoding, HandshakeMessage, OpaqueMessage, RequestMessage,
    ResponseMessage, SealedEnvelope, ServerMessage, SessionId,
    SessionRequest, SessionState, TransparentMessage,
};

/// Version for binary encoding.
pub const VERSION: u16 = 1;

async fn encode_buffer<W: AsyncWrite + AsyncSeek + Unpin + Send>(
    writer: &mut BinaryWriter<W>,
    buffer: &[u8],
) -> Result<()> {
    writer.write_u32(buffer.len() as u32).await?;
    writer.write_bytes(buffer).await?;
    Ok(())
}

async fn decode_buffer<R: AsyncRead + AsyncSeek + Unpin + Send>(
    reader: &mut BinaryReader<R>,
) -> Result<Vec<u8>> {
    let size = reader.read_u32().await?;
    let buf = reader.read_bytes(size as usize).await?;
    Ok(buf)
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
                encode_buffer(writer, buf).await?;
            }
            Self::Responder(len, buf) => {
                writer.write_usize(len).await?;
                encode_buffer(writer, buf).await?;
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
                let buf = decode_buffer(reader).await?;
                *self = HandshakeMessage::Initiator(len, buf);
            }
            types::HANDSHAKE_RESPONDER => {
                let len = reader.read_usize().await?;
                let buf = decode_buffer(reader).await?;
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
                encode_buffer(writer, public_key).await?;
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
                let public_key = decode_buffer(reader).await?;
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
                encode_buffer(writer, peer_key).await?;
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
            Self::CloseSession(session_id) => {
                writer.write_bytes(session_id.as_bytes()).await?;
            }
            Self::SessionFinished(session_id) => {
                writer.write_bytes(session_id.as_bytes()).await?;
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
                let peer_key = decode_buffer(reader).await?;

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
            types::SESSION_CLOSE => {
                let session_id = SessionId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                *self = ServerMessage::CloseSession(session_id);
            }
            types::SESSION_FINISHED => {
                let session_id = SessionId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                *self = ServerMessage::SessionFinished(session_id);
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
                encode_buffer(writer, public_key).await?;
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
                let public_key = decode_buffer(reader).await?;
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
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        Ok(())
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
            _ => {
                return Err(encoding_error(
                    crate::Error::EncodingKind(id),
                ))
            }
        }
        Ok(())
    }
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
        writer.write_bool(self.broadcast).await?;
        writer.write_usize(self.length).await?;
        encode_buffer(writer, &self.payload).await?;
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
        self.broadcast = reader.read_bool().await?;
        self.length = reader.read_usize().await?;
        self.payload = decode_buffer(reader).await?;
        Ok(())
    }
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
            encode_buffer(writer, key).await?;
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
            let key = decode_buffer(reader).await?;
            self.participant_keys.push(key);
        }
        Ok(())
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
        for key in &self.all_participants {
            encode_buffer(writer, key).await?;
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
            let key = decode_buffer(reader).await?;
            self.all_participants.push(key);
        }
        Ok(())
    }
}
