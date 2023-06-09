use axum::http::StatusCode;
use std::sync::Arc;
use tokio::sync::mpsc;

use mpc_relay_protocol::{
    channel::{decrypt_server_channel, encrypt_server_channel},
    decode, encode, hex, Encoding, HandshakeType, ProtocolState,
    RequestMessage, ResponseMessage, SessionResponse,
};

use crate::{server::State, websocket::Connection, Error, Result};

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
        RequestMessage::HandshakeInitiator(
            HandshakeType::Server,
            len,
            buf,
        ) => {
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
                HandshakeType::Server,
                len,
                payload,
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
            handshake,
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
                    handshake,
                    public_key: from_public_key,
                    message,
                };
                let buffer = encode(&relayed).await?;
                writer.send(buffer).await?;
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    public_key,
                )));
            }
        }
        RequestMessage::Envelope(message) => {
            let from_public_key = {
                let reader = conn.read().await;
                reader.public_key.clone()
            };

            let peer = {
                let reader = state.read().await;
                reader.active.get(&from_public_key).map(Arc::clone)
            };

            if let Some(peer) = peer {
                let mut writer = peer.write().await;
                let peer_state = writer.state.as_mut().unwrap();

                let (encoding, contents) =
                    decrypt_server_channel(peer_state, message)
                        .await?;

                if let Encoding::Blob = encoding {
                    let request: RequestMessage =
                        decode(&contents).await?;

                    if let Some(response) =
                        service(state, conn, from_public_key, request).await?
                    {
                        let payload = encode(&response).await?;
                        let inner = encrypt_server_channel(
                            peer_state, payload,
                        )
                        .await?;

                        let response =
                            ResponseMessage::Envelope(inner);
                        let buffer = encode(&response).await?;

                        writer.send(buffer).await?;
                    }
                }
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    from_public_key,
                )));
            }
        }
        _ => {}
    }
    Ok(())
}

async fn service(
    state: State,
    conn: Connection,
    public_key: Vec<u8>,
    message: RequestMessage,
) -> Result<Option<ResponseMessage>> {
    match message {
        RequestMessage::Session(request) => {
            let mut writer = state.write().await;
            let session_id = writer.sessions.new_session(
                public_key,
                request.participant_keys,
            );
            let response = SessionResponse { session_id };
            Ok(Some(ResponseMessage::Session(response)))
        }
        _ => Ok(None),
    }
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
