use axum::http::StatusCode;
use std::sync::Arc;
use tokio::sync::mpsc;

use mpc_relay_protocol::{
    channel::{decrypt_server_channel, encrypt_server_channel},
    decode, encode, hex, Encoding, HandshakeMessage, OpaqueMessage,
    ProtocolState, RequestMessage, ResponseMessage, ServerMessage,
    SessionState, TransparentMessage,
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
                // FIXME: return errors for both transport states!
                let response = ServerMessage::Error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    e.to_string(),
                );
                send_message(Arc::clone(&conn), &response, false)
                    .await?;
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
        RequestMessage::Transparent(
            TransparentMessage::ServerHandshake(
                HandshakeMessage::Initiator(len, buf),
            ),
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

            let response = ResponseMessage::Transparent(
                TransparentMessage::ServerHandshake(
                    HandshakeMessage::Responder(len, payload),
                ),
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
        RequestMessage::Transparent(
            TransparentMessage::PeerHandshake {
                public_key,
                message,
            },
        ) => {
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

                let relayed = ResponseMessage::Transparent(
                    TransparentMessage::PeerHandshake {
                        public_key: from_public_key,
                        message,
                    },
                );

                let buffer = encode(&relayed).await?;
                writer.send(buffer).await?;
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    public_key,
                )));
            }
        }
        RequestMessage::Opaque(OpaqueMessage::PeerMessage {
            public_key,
            session_id,
            envelope,
        }) => {
            // When we have a session identifier check the session
            // is valid and the target peer is a session participant.
            if let Some(id) = session_id {
                let mut writer = state.write().await;
                if let Some(session) =
                    writer.sessions.touch_session(&id)
                {
                    let public_keys = session.public_keys();
                    let is_participant = public_keys
                        .into_iter()
                        .any(|k| k == public_key);

                    if !is_participant {
                        return Err(Error::NotSessionParticipant(
                            id,
                            hex::encode(public_key),
                        ));
                    }
                } else {
                    return Err(Error::SessionNotFound(id));
                }
            }

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

                let relayed = ResponseMessage::Opaque(
                    OpaqueMessage::PeerMessage {
                        public_key: from_public_key,
                        session_id,
                        envelope,
                    },
                );

                let buffer = encode(&relayed).await?;
                writer.send(buffer).await?;
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    public_key,
                )));
            }
        }
        RequestMessage::Opaque(OpaqueMessage::ServerMessage(
            envelope,
        )) => {
            let from_public_key = {
                let reader = conn.read().await;
                reader.public_key.clone()
            };

            let peer = {
                let reader = state.read().await;
                reader.active.get(&from_public_key).map(Arc::clone)
            };

            if let Some(peer) = peer {
                let (encoding, contents) = {
                    let mut writer = peer.write().await;
                    let peer_state = writer.state.as_mut().unwrap();
                    decrypt_server_channel(peer_state, envelope)
                        .await?
                };

                if let Encoding::Blob = encoding {
                    let request: ServerMessage =
                        decode(&contents).await?;

                    if let Some(response) = service(
                        Arc::clone(&state),
                        Arc::clone(&conn),
                        &from_public_key,
                        request,
                    )
                    .await?
                    {
                        send_message(conn, &response, false).await?;
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
    public_key: impl AsRef<[u8]>,
    message: ServerMessage,
) -> Result<Option<ServerMessage>> {
    match message {
        ServerMessage::NewSession(request) => {
            let mut all_participants =
                request.participant_keys.clone();
            all_participants.push(public_key.as_ref().to_vec());

            let session_id = {
                let mut writer = state.write().await;
                let session_id = writer.sessions.new_session(
                    public_key.as_ref().to_vec(),
                    request.participant_keys,
                );
                session_id
            };

            let response = SessionState {
                session_id,
                all_participants,
            };

            Ok(Some(ServerMessage::SessionCreated(response)))
        }
        ServerMessage::SessionReadyNotify(session_id) => {
            let notification = {
                let reader = state.read().await;
                if let Some(session) =
                    reader.sessions.get_session(&session_id)
                {
                    let all_participants = session.public_keys();
                    let total_participants = all_participants.len();
                    let connected: Vec<_> = all_participants
                        .iter()
                        .map(|&key| reader.active.get(key).is_some())
                        .collect();

                    if connected.len() == total_participants {
                        let session = SessionState {
                            session_id,
                            all_participants: all_participants
                                .iter()
                                .map(|k| k.to_vec())
                                .collect(),
                        };
                        let message =
                            ServerMessage::SessionReady(session);
                        let public_keys: Vec<Vec<u8>> =
                            all_participants
                                .into_iter()
                                .map(|key| key.to_vec())
                                .collect();
                        Some((message, public_keys))
                    } else {
                        None
                    }
                } else {
                    return Err(Error::SessionNotFound(session_id));
                }
            };

            if let Some((message, public_keys)) = notification {
                notify_peers(state, public_keys, message).await?;
            }
            Ok(None)
        }
        ServerMessage::SessionConnection {
            session_id,
            peer_key,
        } => {
            let from_public_key = {
                let reader = conn.read().await;
                reader.public_key.clone()
            };

            let mut writer = state.write().await;
            if let Some(session) =
                writer.sessions.get_session_mut(&session_id)
            {
                session
                    .register_connection(from_public_key, peer_key);
                Ok(None)
            } else {
                Err(Error::SessionNotFound(session_id))
            }
        }
        ServerMessage::SessionActiveNotify(session_id) => {
            let notification = {
                let reader = state.read().await;
                if let Some(session) =
                    reader.sessions.get_session(&session_id)
                {
                    if session.is_active() {
                        let all_participants = session.public_keys();
                        let session = SessionState {
                            session_id,
                            all_participants: all_participants
                                .iter()
                                .map(|k| k.to_vec())
                                .collect(),
                        };
                        let message =
                            ServerMessage::SessionActive(session);

                        let public_keys: Vec<Vec<u8>> =
                            all_participants
                                .into_iter()
                                .map(|key| key.to_vec())
                                .collect();
                        Some((message, public_keys))
                    } else {
                        None
                    }
                } else {
                    return Err(Error::SessionNotFound(session_id));
                }
            };

            if let Some((message, public_keys)) = notification {
                notify_peers(state, public_keys, message).await?;
            }
            Ok(None)
        }
        ServerMessage::CloseSession(session_id) => {
            {
                let reader = state.read().await;
                if let Some(session) =
                    reader.sessions.get_session(&session_id)
                {
                    if public_key.as_ref() != session.owner_key() {
                        return Err(Error::PermissionDenied);
                    }
                } else {
                    return Err(Error::SessionNotFound(session_id));
                }
            }

            let mut writer = state.write().await;
            writer.sessions.remove_session(&session_id);

            Ok(Some(ServerMessage::SessionFinished(session_id)))
        }
        _ => Ok(None),
    }
}

/// Send a message to a collection of peers.
async fn notify_peers(
    state: State,
    public_keys: Vec<Vec<u8>>,
    message: ServerMessage,
) -> Result<()> {
    let reader = state.read().await;
    for key in &public_keys {
        if let Some(conn) = reader.active.get(key).map(Arc::clone) {
            send_message(conn, &message, true).await?;
        }
    }
    Ok(())
}

/// Send a response message to a client over the server channel.
async fn send_message(
    conn: Connection,
    message: &ServerMessage,
    broadcast: bool,
) -> Result<()> {
    let mut writer = conn.write().await;

    let payload = encode(message).await?;
    let envelope = encrypt_server_channel(
        writer.state.as_mut().unwrap(),
        payload,
        broadcast,
    )
    .await?;

    let response = ResponseMessage::Opaque(
        OpaqueMessage::ServerMessage(envelope),
    );
    let buffer = encode(&response).await?;

    writer.send(buffer).await?;
    Ok(())
}

/// Promote a connection from pending to active state.
///
/// Called once the server handshake has been initiated.
async fn promote_connection(state: State, conn: Connection) {
    let (id, public_key) = {
        let reader = conn.read().await;
        (reader.id, reader.public_key.clone())
    };
    let mut writer = state.write().await;
    writer.pending.remove(&id);
    writer.active.insert(public_key, conn);
}
