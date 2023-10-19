use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::{collections::HashSet, io::Result};

use crate::{
    encoding::{
        decode_preamble, encode_preamble, encoding_error, types,
        MAX_BUFFER_SIZE,
    },
    Encoding, Error, HandshakeMessage, MeetingId, MeetingState,
    OpaqueMessage, RequestMessage, ResponseMessage, SealedEnvelope,
    ServerMessage, SessionId, SessionRequest, SessionState,
    TransparentMessage,
};

/// Version for binary encoding.
pub const VERSION: u16 = 1;

/// Encode a length-prefixed buffer.
async fn encode_buffer<W: AsyncWrite + AsyncSeek + Unpin + Send>(
    writer: &mut BinaryWriter<W>,
    buffer: &[u8],
) -> Result<()> {
    if buffer.len() > MAX_BUFFER_SIZE {
        return Err(encoding_error(Error::MaxBufferSize(
            MAX_BUFFER_SIZE,
        )));
    }
    writer.write_u16(buffer.len() as u16).await?;
    writer.write_bytes(buffer).await?;
    Ok(())
}

/// Decode a length-prefixed buffer.
async fn decode_buffer<R: AsyncRead + AsyncSeek + Unpin + Send>(
    reader: &mut BinaryReader<R>,
) -> Result<Vec<u8>> {
    let size = reader.read_u16().await?;
    let buf = reader.read_bytes(size as usize).await?;
    Ok(buf)
}

/// Encode an encrypted payload with an additional length prefix
/// indicating the length of the encrypted buffer.
async fn encode_payload<W: AsyncWrite + AsyncSeek + Unpin + Send>(
    writer: &mut BinaryWriter<W>,
    length: &usize,
    buffer: &[u8],
) -> Result<()> {
    if *length > MAX_BUFFER_SIZE {
        return Err(encoding_error(Error::MaxBufferSize(
            MAX_BUFFER_SIZE,
        )));
    }
    writer.write_u16(*length as u16).await?;
    encode_buffer(writer, buffer).await?;
    Ok(())
}

/// Decode an encrypted payload with an additional length prefix
/// indicating the length of the encrypted buffer.
async fn decode_payload<R: AsyncRead + AsyncSeek + Unpin + Send>(
    reader: &mut BinaryReader<R>,
) -> Result<(usize, Vec<u8>)> {
    let length = reader.read_u16().await? as usize;
    let buffer = decode_buffer(reader).await?;
    Ok((length, buffer))
}

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[async_trait]
impl Encodable for HandshakeMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        match self {
            Self::Initiator(len, buf) => {
                encode_payload(writer, len, buf).await?;
            }
            Self::Responder(len, buf) => {
                encode_payload(writer, len, buf).await?;
            }
            Self::Noop => unreachable!(),
        }
        Ok(())
    }
}

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Decodable for HandshakeMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            types::HANDSHAKE_INITIATOR => {
                let (len, buf) = decode_payload(reader).await?;
                *self = HandshakeMessage::Initiator(len, buf);
            }
            types::HANDSHAKE_RESPONDER => {
                let (len, buf) = decode_payload(reader).await?;
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Encodable for TransparentMessage {
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Decodable for TransparentMessage {
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
                *self = TransparentMessage::Error(code, message);
            }
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
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
            Self::NewMeeting { owner_id, slots } => {
                writer.write_bytes(owner_id.as_ref()).await?;
                writer.write_u32(slots.len() as u32).await?;
                for slot in slots {
                    writer.write_bytes(slot.as_ref()).await?;
                }
            }
            Self::MeetingCreated(response) => {
                response.encode(writer).await?;
            }
            Self::JoinMeeting(meeting_id, user_id) => {
                writer.write_bytes(meeting_id.as_bytes()).await?;
                writer.write_bytes(user_id.as_ref()).await?;
            }
            Self::MeetingReady(response) => {
                response.encode(writer).await?;
            }
            Self::NewSession(request) => {
                request.encode(writer).await?;
            }
            Self::SessionConnection {
                session_id,
                peer_key,
            } => {
                writer.write_bytes(session_id.as_bytes()).await?;
                encode_buffer(writer, peer_key).await?;
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
            Self::SessionTimeout(session_id) => {
                writer.write_bytes(session_id.as_bytes()).await?;
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
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
            types::MEETING_NEW => {
                let owner_id: [u8; 32] =
                    reader.read_bytes(32).await?.try_into().unwrap();

                let mut slots = HashSet::new();
                let num_slots = reader.read_u32().await?;
                for _ in 0..num_slots {
                    let slot: [u8; 32] = reader
                        .read_bytes(32)
                        .await?
                        .try_into()
                        .unwrap();
                    slots.insert(slot.into());
                }
                *self = ServerMessage::NewMeeting {
                    owner_id: owner_id.into(),
                    slots,
                };
            }
            types::MEETING_CREATED => {
                let mut meeting: MeetingState = Default::default();
                meeting.decode(reader).await?;
                *self = ServerMessage::MeetingCreated(meeting);
            }
            types::MEETING_JOIN => {
                let meeting_id = MeetingId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                let user_id: [u8; 32] =
                    reader.read_bytes(32).await?.try_into().unwrap();

                *self = ServerMessage::JoinMeeting(
                    meeting_id,
                    user_id.into(),
                );
            }
            types::MEETING_READY => {
                let mut meeting: MeetingState = Default::default();
                meeting.decode(reader).await?;
                *self = ServerMessage::MeetingReady(meeting);
            }
            types::SESSION_NEW => {
                let mut session: SessionRequest = Default::default();
                session.decode(reader).await?;
                *self = ServerMessage::NewSession(session);
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
            types::SESSION_TIMEOUT => {
                let session_id = SessionId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                *self = ServerMessage::SessionTimeout(session_id);
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Encodable for RequestMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        encode_preamble(writer).await?;
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Decodable for RequestMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        decode_preamble(reader).await?;
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Encodable for ResponseMessage {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        encode_preamble(writer).await?;
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

//#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
//#[cfg_attr(not(target_arch = "wasm32"), async_trait)]

#[async_trait]
impl Decodable for ResponseMessage {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        decode_preamble(reader).await?;
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

#[async_trait]
impl Encodable for SealedEnvelope {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.encoding.into();
        writer.write_u8(id).await?;
        writer.write_bool(self.broadcast).await?;

        encode_payload(writer, &self.length, &self.payload).await?;

        Ok(())
    }
}

#[async_trait]
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
        let (length, payload) = decode_payload(reader).await?;
        self.length = length;
        self.payload = payload;
        Ok(())
    }
}

#[async_trait]
impl Encodable for SessionRequest {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // TODO: handle too many participants
        writer.write_u16(self.participant_keys.len() as u16).await?;
        for key in self.participant_keys.iter() {
            encode_buffer(writer, key).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for SessionRequest {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let size = reader.read_u16().await? as usize;
        for _ in 0..size {
            let key = decode_buffer(reader).await?;
            self.participant_keys.push(key);
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for MeetingState {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.meeting_id.as_bytes()).await?;
        writer
            .write_u16(self.registered_participants.len() as u16)
            .await?;
        for key in &self.registered_participants {
            encode_buffer(writer, key).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for MeetingState {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.meeting_id = MeetingId::from_bytes(
            reader
                .read_bytes(16)
                .await?
                .as_slice()
                .try_into()
                .map_err(encoding_error)?,
        );
        let size = reader.read_u16().await? as usize;
        for _ in 0..size {
            let key = decode_buffer(reader).await?;
            self.registered_participants.push(key);
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for SessionState {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.session_id.as_bytes()).await?;
        writer.write_u16(self.all_participants.len() as u16).await?;
        for key in &self.all_participants {
            encode_buffer(writer, key).await?;
        }
        Ok(())
    }
}

#[async_trait]
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
        let size = reader.read_u16().await? as usize;
        for _ in 0..size {
            let key = decode_buffer(reader).await?;
            self.all_participants.push(key);
        }
        Ok(())
    }
}
