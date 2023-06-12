use futures::{sink::SinkExt, stream::Stream, Future, StreamExt};

use std::{pin::Pin, sync::Arc};
use tokio::sync::mpsc;

use mpc_relay_protocol::{
    channel::decrypt_server_channel, decode, hex, snow::Builder,
    Encoding, HandshakeMessage, OpaqueMessage, ProtocolState,
    RequestMessage, ResponseMessage, SealedEnvelope, ServerMessage,
    SessionId, SessionState, TransparentMessage, PATTERN,
};

use super::{decrypt_peer_channel, Peers, Server};
use crate::{ClientOptions, Error, Result};

/// Message builder converts request messages to be
/// send into the type expected by the websocket write
/// stream.
pub type MessageBuilder<T> = Box<
    dyn Fn(
            RequestMessage,
        ) -> Pin<Box<dyn Future<Output = Result<T>> + Send>>
        + Send
        + Sync,
>;

/// Events dispatched by the event loop stream.
#[derive(Debug)]
pub enum Event {
    /// Event dispatched when a handshake with the server
    /// is completed.
    ServerConnected {
        /// Public key of the server.
        server_key: Vec<u8>,
    },
    /// Event dispatched when a handshake with a peer
    /// has been completed.
    PeerConnected {
        /// Public key of the peer.
        peer_key: Vec<u8>,
    },
    /// Binary message received from a peer.
    BinaryMessage {
        /// Public key of the peer.
        peer_key: Vec<u8>,
        /// Message buffer.
        message: Vec<u8>,
        /// Session identifier.
        session_id: Option<SessionId>,
    },
    /// JSON message received from a peer.
    JsonMessage {
        /// Public key of the peer.
        peer_key: Vec<u8>,
        /// JSON message.
        message: JsonMessage,
        /// Session identifier.
        session_id: Option<SessionId>,
    },
    /// Event dispatched when a session has been created.
    SessionCreated(SessionState),

    /// Event dispatched when a session is ready.
    ///
    /// A session is ready when all participants
    /// have completed the server handshake.
    ///
    /// Peers can now handshake with each other.
    SessionReady(SessionState),

    /// Event dispatched when a session is active.
    ///
    /// A session is active when all the participants
    /// have connected to each other.
    SessionActive(SessionState),

    /// Event dispatched when a session has been finished.
    ///
    /// A session can only be finished when the session owner
    /// explicitly closes the session.
    SessionFinished(SessionId),
}

/// JSON message received from a peer.
#[derive(Debug)]
pub struct JsonMessage {
    contents: Vec<u8>,
}

impl JsonMessage {
    /// Deserialize this message.
    pub fn deserialize<'a, T: serde::de::Deserialize<'a>>(
        &'a self,
    ) -> Result<T> {
        Ok(serde_json::from_slice::<T>(&self.contents)?)
    }
}

/// Event loop for a websocket client.
pub struct EventLoop<M, E, R, W>
where
    M: Send + Sync,
    E: Send + Sync,
    R: Stream<Item = std::result::Result<M, E>> + Unpin,
    W: SinkExt<M> + Unpin,
{
    pub(crate) options: Arc<ClientOptions>,
    pub(crate) ws_reader: R,
    pub(crate) ws_writer: W,
    pub(crate) message_tx: mpsc::Sender<ResponseMessage>,
    pub(crate) message_rx: mpsc::Receiver<ResponseMessage>,
    pub(crate) outbound_tx: mpsc::Sender<RequestMessage>,
    pub(crate) outbound_rx: mpsc::Receiver<RequestMessage>,
    pub(crate) server: Server,
    pub(crate) peers: Peers,
    pub(crate) builder: MessageBuilder<M>,
}

impl<M, E, R, W> EventLoop<M, E, R, W>
where
    M: Send + Sync,
    E: Send + Sync,
    R: Stream<Item = std::result::Result<M, E>> + Unpin,
    W: SinkExt<M> + Unpin,
{
    /// Send a message to the socket and flush the stream.
    pub(crate) async fn send_message(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let message = (self.builder)(message).await?;
        self.ws_writer
            .send(message)
            .await
            .map_err(|_| Error::WebSocketSend)?;
        Ok(self
            .ws_writer
            .flush()
            .await
            .map_err(|_| Error::WebSocketSend)?)
    }

    pub(crate) async fn handle_incoming_message(
        &mut self,
        incoming: ResponseMessage,
    ) -> Result<Option<Event>> {
        match incoming {
            ResponseMessage::Transparent(
                TransparentMessage::Error(code, message),
            ) => Err(Error::ServerError(code, message)),
            ResponseMessage::Transparent(
                TransparentMessage::ServerHandshake(
                    HandshakeMessage::Responder(len, buf),
                ),
            ) => Ok(Some(self.server_handshake(len, buf).await?)),
            ResponseMessage::Transparent(
                TransparentMessage::PeerHandshake {
                    message: HandshakeMessage::Initiator(len, buf),
                    public_key,
                },
            ) => Ok(self
                .peer_handshake_responder(public_key, len, buf)
                .await?),
            ResponseMessage::Transparent(
                TransparentMessage::PeerHandshake {
                    message: HandshakeMessage::Responder(len, buf),
                    public_key,
                },
            ) => Ok(Some(
                self.peer_handshake_ack(public_key, len, buf).await?,
            )),
            ResponseMessage::Opaque(OpaqueMessage::PeerMessage {
                public_key,
                envelope,
                session_id,
            }) => Ok(Some(
                self.handle_relayed_message(
                    public_key, envelope, session_id,
                )
                .await?,
            )),
            ResponseMessage::Opaque(
                OpaqueMessage::ServerMessage(envelope),
            ) => {
                let mut server = self.server.write().await;
                if let Some(server) = server.as_mut() {
                    let (encoding, contents) =
                        decrypt_server_channel(server, envelope)
                            .await?;
                    let message = match encoding {
                        Encoding::Blob => {
                            let response: ServerMessage =
                                decode(&contents).await?;
                            response
                        }
                        _ => {
                            panic!("unexpected encoding received from server")
                        }
                    };
                    Ok(self
                        .handle_server_channel_message(message)
                        .await?)
                } else {
                    unreachable!()
                }
            }
            _ => {
                panic!("unhandled message");
            }
        }
    }

    /// Process an inner message from the server after
    /// decrypting the envelope.
    async fn handle_server_channel_message(
        &self,
        message: ServerMessage,
    ) -> Result<Option<Event>> {
        match message {
            ServerMessage::Error(code, message) => {
                Err(Error::ServerError(code, message))
            }
            ServerMessage::SessionCreated(response) => {
                Ok(Some(Event::SessionCreated(response)))
            }
            ServerMessage::SessionReady(response) => {
                Ok(Some(Event::SessionReady(response)))
            }
            ServerMessage::SessionActive(response) => {
                Ok(Some(Event::SessionActive(response)))
            }
            ServerMessage::SessionFinished(session_id) => {
                Ok(Some(Event::SessionFinished(session_id)))
            }
            _ => Ok(None),
        }
    }

    async fn server_handshake(
        &mut self,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Event> {
        let mut state = self.server.write().await;
        let transport = match state.take() {
            Some(ProtocolState::Handshake(mut initiator)) => {
                let mut read_buf = vec![0u8; 1024];
                initiator.read_message(&buf[..len], &mut read_buf)?;

                initiator.into_transport_mode()?
            }
            _ => return Err(Error::NotHandshakeState),
        };

        *state = Some(ProtocolState::Transport(transport));

        Ok(Event::ServerConnected {
            server_key: self.options.server_public_key.clone(),
        })
    }

    async fn peer_handshake_responder(
        &self,
        public_key: impl AsRef<[u8]>,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Option<Event>> {
        let mut peers = self.peers.write().await;

        if peers.get(public_key.as_ref()).is_some() {
            return Err(Error::PeerAlreadyExistsMaybeRace);
        } else {
            tracing::debug!(
                from = ?hex::encode(public_key.as_ref()),
                "peer handshake responder"
            );

            let builder = Builder::new(PATTERN.parse()?);
            let mut responder = builder
                .local_private_key(&self.options.keypair.private)
                .remote_public_key(public_key.as_ref())
                .build_responder()?;

            let mut read_buf = vec![0u8; 1024];
            responder.read_message(&buf[..len], &mut read_buf)?;

            let mut payload = vec![0u8; 1024];
            let len = responder.write_message(&[], &mut payload)?;

            let transport = responder.into_transport_mode()?;
            peers.insert(
                public_key.as_ref().to_vec(),
                ProtocolState::Transport(transport),
            );

            let request = RequestMessage::Transparent(
                TransparentMessage::PeerHandshake {
                    public_key: public_key.as_ref().to_vec(),
                    message: HandshakeMessage::Responder(
                        len, payload,
                    ),
                },
            );

            self.outbound_tx.send(request).await?;

            Ok(Some(Event::PeerConnected {
                peer_key: public_key.as_ref().to_vec(),
            }))
        }
    }

    async fn peer_handshake_ack(
        &self,
        public_key: impl AsRef<[u8]>,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Event> {
        let mut peers = self.peers.write().await;

        let peer =
            if let Some(peer) = peers.remove(public_key.as_ref()) {
                peer
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    public_key.as_ref().to_vec(),
                )));
            };

        tracing::debug!(
            from = ?hex::encode(public_key.as_ref()),
            "peer handshake done"
        );

        let transport = match peer {
            ProtocolState::Handshake(mut initiator) => {
                let mut read_buf = vec![0u8; 1024];
                initiator.read_message(&buf[..len], &mut read_buf)?;
                initiator.into_transport_mode()?
            }
            _ => return Err(Error::NotHandshakeState),
        };

        peers.insert(
            public_key.as_ref().to_vec(),
            ProtocolState::Transport(transport),
        );

        Ok(Event::PeerConnected {
            peer_key: public_key.as_ref().to_vec(),
        })
    }

    async fn handle_relayed_message(
        &mut self,
        public_key: impl AsRef<[u8]>,
        envelope: SealedEnvelope,
        session_id: Option<SessionId>,
    ) -> Result<Event> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(public_key.as_ref()) {
            let contents =
                decrypt_peer_channel(peer, &envelope).await?;
            match envelope.encoding {
                Encoding::Noop => unreachable!(),
                Encoding::Blob => Ok(Event::BinaryMessage {
                    peer_key: public_key.as_ref().to_vec(),
                    message: contents,
                    session_id,
                }),
                Encoding::Json => Ok(Event::JsonMessage {
                    peer_key: public_key.as_ref().to_vec(),
                    message: JsonMessage { contents },
                    session_id,
                }),
            }
        } else {
            Err(Error::PeerNotFound(hex::encode(
                public_key.as_ref().to_vec(),
            )))
        }
    }
}
