//! Utility functions for the encrypted server channel.
//!
//! You should not use these functions directly, they are
//! exposed so they can be shared between the client and server.
use crate::{
    Encoding, Error, ProtocolState, Result, SealedEnvelope, Chunk,
};

/// Encrypt a message to send to the server.
///
/// The protocol must be in transport mode.
#[doc(hidden)]
pub async fn encrypt_server_channel(
    server: &mut ProtocolState,
    payload: &[u8],
    broadcast: bool,
) -> Result<SealedEnvelope> {
    match server {
        ProtocolState::Transport(transport) => {
            let chunks = Chunk::split(payload, transport)?;
            let envelope = SealedEnvelope {
                encoding: Encoding::Blob,
                chunks,
                broadcast,
            };
            Ok(envelope)
        }
        _ => Err(Error::NotTransportState),
    }
}

/// Decrypt a message received from the server.
///
/// The protocol must be in transport mode.
#[doc(hidden)]
pub async fn decrypt_server_channel(
    server: &mut ProtocolState,
    envelope: SealedEnvelope,
) -> Result<(Encoding, Vec<u8>)> {
    match server {
        ProtocolState::Transport(transport) => {
            let contents = Chunk::join(envelope.chunks, transport)?;
            Ok((envelope.encoding, contents))
        }
        _ => Err(Error::NotTransportState),
    }
}
