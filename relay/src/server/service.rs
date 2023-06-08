use super::{Connection, State};
use crate::{
    decode, encode, Error, ProtocolState, RequestMessage,
    ResponseMessage, Result,
};
use axum::http::StatusCode;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct RelayService {
    state: State,
}

impl RelayService {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    /// Start listening for messages on a websocket.
    pub(crate) fn listen_socket(
        &self,
        conn: Connection,
        reader: mpsc::Receiver<Vec<u8>>,
        _writer: mpsc::Sender<Vec<u8>>,
    ) {
        tokio::spawn(listen(
            Arc::clone(&self.state),
            Arc::clone(&conn),
            reader,
        ));
    }
}

async fn listen(
    state: State,
    conn: Connection,
    mut read_channel: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(buffer) = read_channel.recv().await {
        let message: RequestMessage = decode(&buffer).await?;
        match handle_request(
            Arc::clone(&state),
            Arc::clone(&conn),
            message,
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                let mut writer = conn.write().await;
                let response = ResponseMessage::Error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    e.to_string(),
                );
                let buffer = encode(&response).await?;
                writer.send(buffer).await?;
            }
        }
    }
    Ok(())
}

async fn handle_request(
    state: State,
    conn: Connection,
    message: RequestMessage,
) -> Result<()> {
    match message {
        RequestMessage::HandshakeInitiator(kind, len, buf) => {
            let mut writer = conn.write().await;
            let (len, payload) = match &mut writer.state {
                Some(ProtocolState::Handshake(responder)) => {
                    let mut reply = vec![0u8; 1024];
                    let mut read_buf = vec![0u8; 1024];
                    responder
                        .read_message(&buf[..len], &mut read_buf)?;
                    let len =
                        responder.write_message(&[], &mut reply)?;

                    (len, reply)
                }
                _ => return Err(Error::NotHandshakeState),
            };

            let response = ResponseMessage::HandshakeResponder(
                kind, len, payload,
            );
            let buffer = encode(&response).await?;
            writer.send(buffer).await?;

            if let Some(ProtocolState::Handshake(state)) =
                writer.state.take()
            {
                let transport = state.into_transport_mode()?;
                writer.state =
                    Some(ProtocolState::Transport(transport));
            } else {
                unreachable!();
            }

            drop(writer);

            // Now move from pending to transport active
            promote_connection(Arc::clone(&state), Arc::clone(&conn))
                .await;
        }
        RequestMessage::RelayPeer {
            public_key,
            message,
        } => {
            let from_public_key = {
                let reader = conn.read().await;
                reader.public_key.clone()
            };

            let peer = {
                let reader = state.read().await;
                reader.active.get(&public_key).map(Arc::clone)
            };

            if let Some(peer) = peer {
                let mut writer = peer.write().await;

                tracing::debug!(
                    to = ?hex::encode(&public_key),
                    from = ?hex::encode(&from_public_key),
                    "relay",
                );
                let relayed = ResponseMessage::RelayPeer {
                    public_key: from_public_key,
                    message,
                };
                let buffer = encode(&relayed).await?;
                //println!("relaying the peer message {:#?}", writer.public_key);
                writer.send(buffer).await?;
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    public_key,
                )));
            }
        }
        RequestMessage::Noop => {}
    }

    Ok(())
}

/// Promote a connection from pending to active state.
///
/// Called once the server handshake has been initiated.
async fn promote_connection(state: State, conn: Connection) {
    let (id, public_key) = {
        let reader = conn.read().await;
        (reader.id.clone(), reader.public_key.clone())
    };
    let mut writer = state.write().await;
    writer.pending.remove(&id);
    writer.active.insert(public_key, conn);
}
