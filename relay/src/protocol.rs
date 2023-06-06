use snow::{HandshakeState, TransportState};
use futures::io::{AsyncWrite, AsyncRead, AsyncSeek};
use async_trait::async_trait;
use binary_stream::futures::{Encodable, Decodable, BinaryWriter, BinaryReader};
use std::io::{Error, Result};

pub(crate) fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

mod types {
    pub const HANDSHAKE_INITIATOR: u8 = 1;
    pub const HANDSHAKE_RESPONDER: u8 = 2;
}

/// Enumeration of protocol states.
pub enum ProtocolState {
    /// Noise handshake state.
    Handshake(HandshakeState),
    /// Noise transport state.
    Transport(TransportState),
}

/// Request messages from the client.
pub enum RequestMessage {
    /// Initiate a handshake.
    HandshakeInitiator(Vec<u8>),
}

impl From<&RequestMessage> for u8 {
    fn from(value: &RequestMessage) -> Self {
        match value {
            RequestMessage::HandshakeInitiator(_) => {
                types::HANDSHAKE_INITIATOR
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
            Self::HandshakeInitiator(buf) => {
                writer.write_u32(buf.len() as u32).await?;
                writer.write_bytes(buf).await?;
            }
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
                let len = reader.read_u32().await?;
                let buf = reader.read_bytes(len as usize).await?;
                *self = RequestMessage::HandshakeInitiator(buf);
            }
            _ => return Err(encoding_error(crate::Error::MessageKind(id)))
        }
        Ok(())
    }
}

/// Response messages from the server.
pub enum ResponseMessage {
    /// Respond to a handshake initiation.
    HandshakeResponder(Vec<u8>),
}

impl From<&ResponseMessage> for u8 {
    fn from(value: &ResponseMessage) -> Self {
        match value {
            ResponseMessage::HandshakeResponder(_) => {
                types::HANDSHAKE_RESPONDER
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
            Self::HandshakeResponder(buf) => {
                writer.write_u32(buf.len() as u32).await?;
                writer.write_bytes(buf).await?;
            }
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
            types::HANDSHAKE_RESPONDER => {
                let len = reader.read_u32().await?;
                let buf = reader.read_bytes(len as usize).await?;
                *self = ResponseMessage::HandshakeResponder(buf);
            }
            _ => return Err(encoding_error(crate::Error::MessageKind(id)))
        }
        Ok(())
    }
}
