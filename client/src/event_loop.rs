use futures::{sink::SinkExt, stream::Stream};
use std::sync::Arc;
use tokio::sync::mpsc;

use mpc_relay_protocol::{
    channel::decrypt_server_channel, decode, hex, snow::Builder,
    Encoding, HandshakeMessage, OpaqueMessage, ProtocolState,
    RequestMessage, ResponseMessage, SealedEnvelope, ServerMessage,
    SessionId, SessionState, TransparentMessage, PATTERN,
};

use super::{decrypt_peer_channel, Peers, Server};
use crate::{ClientOptions, Error, Result};

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

    /// Event dispatched when a session timed out waiting
    /// for all the participants.
    SessionTimeout(SessionId),

    /// Event dispatched when a session has been finished.
    ///
    /// A session can only be finished when the session owner
    /// explicitly closes the session.
    SessionFinished(SessionId),

    /// Event dispatched when the socket is closed.
    Close,
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

/// Internal message used to communicate between
/// the client and event loop.
#[doc(hidden)]
#[derive(Debug)]
pub enum InternalMessage {
    /// Send a request.
    Request(RequestMessage),
    /// Close the connection.
    Close,
}

/// Event loop for a websocket client.
pub struct EventLoop<M, E, R, W>
where
    M: Send,
    E: Send,
    R: Stream<Item = std::result::Result<M, E>> + Unpin,
    W: SinkExt<M> + Unpin,
{
    pub(crate) options: Arc<ClientOptions>,
    pub(crate) ws_reader: R,
    pub(crate) ws_writer: W,
    pub(crate) inbound_tx: mpsc::Sender<ResponseMessage>,
    pub(crate) inbound_rx: mpsc::Receiver<ResponseMessage>,
    pub(crate) outbound_tx: mpsc::Sender<InternalMessage>,
    pub(crate) outbound_rx: mpsc::Receiver<InternalMessage>,
    pub(crate) server: Server,
    pub(crate) peers: Peers,
}

impl<M, E, R, W> EventLoop<M, E, R, W>
where
    M: Send,
    E: Send,
    R: Stream<Item = std::result::Result<M, E>> + Unpin,
    W: SinkExt<M> + Unpin,
{
    pub(crate) async fn handle_incoming_message(
        options: Arc<ClientOptions>,
        server: Server,
        peers: Peers,
        incoming: ResponseMessage,
        outbound_tx: mpsc::Sender<InternalMessage>,
    ) -> Result<Option<Event>> {
        match incoming {
            ResponseMessage::Transparent(
                TransparentMessage::Error(code, message),
            ) => Err(Error::ServerError(code, message)),
            ResponseMessage::Transparent(
                TransparentMessage::ServerHandshake(
                    HandshakeMessage::Responder(len, buf),
                ),
            ) => Ok(Some(
                Self::server_handshake(options, server, len, buf)
                    .await?,
            )),
            ResponseMessage::Transparent(
                TransparentMessage::PeerHandshake {
                    message: HandshakeMessage::Initiator(len, buf),
                    public_key,
                },
            ) => Ok(Self::peer_handshake_responder(
                options,
                peers,
                outbound_tx,
                public_key,
                len,
                buf,
            )
            .await?),
            ResponseMessage::Transparent(
                TransparentMessage::PeerHandshake {
                    message: HandshakeMessage::Responder(len, buf),
                    public_key,
                },
            ) => Ok(Some(
                Self::peer_handshake_ack(peers, public_key, len, buf)
                    .await?,
            )),
            ResponseMessage::Opaque(OpaqueMessage::PeerMessage {
                public_key,
                envelope,
                session_id,
            }) => Ok(Some(
                Self::handle_relayed_message(
                    peers, public_key, envelope, session_id,
                )
                .await?,
            )),
            ResponseMessage::Opaque(
                OpaqueMessage::ServerMessage(envelope),
            ) => {
                let mut server = server.write().await;
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
                    Ok(Self::handle_server_channel_message(message)
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
    pub(crate) async fn handle_server_channel_message(
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
            ServerMessage::SessionTimeout(session_id) => {
                Ok(Some(Event::SessionTimeout(session_id)))
            }
            ServerMessage::SessionFinished(session_id) => {
                Ok(Some(Event::SessionFinished(session_id)))
            }
            _ => Ok(None),
        }
    }

    async fn server_handshake(
        options: Arc<ClientOptions>,
        server: Server,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Event> {
        let mut state = server.write().await;
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
            server_key: options.server_public_key.clone(),
        })
    }

    async fn peer_handshake_responder(
        options: Arc<ClientOptions>,
        peers: Peers,
        outbound_tx: mpsc::Sender<InternalMessage>,
        public_key: impl AsRef<[u8]>,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Option<Event>> {
        let mut peers = peers.write().await;

        if peers.get(public_key.as_ref()).is_some() {
            Err(Error::PeerAlreadyExistsMaybeRace)
        } else {
            tracing::debug!(
                from = ?hex::encode(public_key.as_ref()),
                "peer handshake responder"
            );

            let builder = Builder::new(PATTERN.parse()?);
            let mut responder = builder
                .local_private_key(&options.keypair.private)
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

            outbound_tx
                .send(InternalMessage::Request(request))
                .await?;

            Ok(Some(Event::PeerConnected {
                peer_key: public_key.as_ref().to_vec(),
            }))
        }
    }

    async fn peer_handshake_ack(
        peers: Peers,
        public_key: impl AsRef<[u8]>,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Event> {
        let mut peers = peers.write().await;

        let peer =
            if let Some(peer) = peers.remove(public_key.as_ref()) {
                peer
            } else {
                return Err(Error::PeerNotFound(hex::encode(
                    public_key.as_ref(),
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
        peers: Peers,
        public_key: impl AsRef<[u8]>,
        envelope: SealedEnvelope,
        session_id: Option<SessionId>,
    ) -> Result<Event> {
        let mut peers = peers.write().await;
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
            Err(Error::PeerNotFound(hex::encode(public_key.as_ref())))
        }
    }
}

#[doc(hidden)]
macro_rules! event_loop_run_impl {
    () => {
        /// Stream of events from the event loop.
        pub fn run(mut self) -> BoxStream<'static, Result<Event>> {
            let options = Arc::clone(&self.options);
            let server = Arc::clone(&self.server);
            let peers = Arc::clone(&self.peers);

            let s = stream! {
                loop {
                    select!(
                        message_in =
                            self.ws_reader.next().fuse()
                                => match message_in {
                            Some(message) => {
                                match message {
                                    Ok(message) => {
                                        if let Err(e) = Self::read_message(
                                            message,
                                            &mut self.inbound_tx,
                                        ).await {
                                            yield Err(e);
                                        }
                                    }
                                    Err(e) => {
                                        yield Err(e.into())
                                    }
                                }
                            }
                            _ => {}
                        },
                        message_out =
                            self.outbound_rx.recv().fuse()
                                => match message_out {
                            Some(message) => {

                                match message {
                                    InternalMessage::Request(request) => {
                                        if let Err(e) = self.send_message(request).await {
                                            yield Err(e)
                                        }
                                    }
                                    InternalMessage::Close => {
                                        if let Err(e) = self.handle_close_message().await {
                                            yield Err(e)
                                        }
                                        yield Ok(Event::Close);
                                        break;
                                    }
                                }

                            }
                            _ => {}
                        },
                        event_message =
                            self.inbound_rx.recv().fuse()
                                => match event_message {
                            Some(event_message) => {
                                match Self::handle_incoming_message(
                                    Arc::clone(&options),
                                    Arc::clone(&server),
                                    Arc::clone(&peers),
                                    event_message,
                                    self.outbound_tx.clone(),
                                ).await {

                                    Ok(Some(event)) => {
                                        yield Ok(event);
                                    }
                                    Err(e) => {
                                        yield Err(e)
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        },
                    );
                }
            };
            Box::pin(s)
        }
    }
}

pub(crate) use event_loop_run_impl;
