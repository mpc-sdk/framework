use futures::{
    sink::SinkExt,
    stream::{BoxStream, Stream},
};
use std::sync::Arc;
use tokio::sync::mpsc;

use polysig_protocol::{
    channel::decrypt_server_channel, decode, hex, snow::Builder,
    Encoding, Event, HandshakeMessage, OpaqueMessage, ProtocolState,
    RequestMessage, ResponseMessage, SealedEnvelope, ServerMessage,
    SessionId, TransparentMessage,
};

use super::{decrypt_peer_channel, Peers, Server};
use crate::{ClientOptions, Error, Result};

/// Stream of events emitted by an event loop.
pub type EventStream = BoxStream<'static, Result<Event>>;

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

/// Event loop for a client.
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
    pub(crate) inbound_tx: mpsc::UnboundedSender<ResponseMessage>,
    pub(crate) inbound_rx: mpsc::UnboundedReceiver<ResponseMessage>,
    pub(crate) outbound_tx: mpsc::UnboundedSender<InternalMessage>,
    pub(crate) outbound_rx: mpsc::UnboundedReceiver<InternalMessage>,
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
        outbound_tx: mpsc::UnboundedSender<InternalMessage>,
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
                            panic!(
                                "unexpected encoding received from server")
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
            ServerMessage::MeetingCreated(response) => {
                Ok(Some(Event::MeetingCreated(response)))
            }
            ServerMessage::MeetingReady(response) => {
                Ok(Some(Event::MeetingReady(response)))
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
        outbound_tx: mpsc::UnboundedSender<InternalMessage>,
        public_key: impl AsRef<[u8]>,
        len: usize,
        buf: Vec<u8>,
    ) -> Result<Option<Event>> {
        let mut peers = peers.write().await;

        if peers.get(public_key.as_ref()).is_some() {
            Err(Error::PeerAlreadyExistsMaybeRace)
            //Ok(None)
        } else {
            tracing::debug!(
                from = ?hex::encode(public_key.as_ref()),
                "peer handshake responder"
            );

            let builder = Builder::new(options.params()?);
            let mut responder = builder
                .local_private_key(options.keypair.private_key())
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

            outbound_tx.send(InternalMessage::Request(request))?;

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
            let (encoding, contents) =
                decrypt_peer_channel(peer, envelope).await?;
            match encoding {
                Encoding::Noop => unreachable!(),
                Encoding::Blob => Ok(Event::BinaryMessage {
                    peer_key: public_key.as_ref().to_vec(),
                    message: contents,
                    session_id,
                }),
                Encoding::Json => Ok(Event::JsonMessage {
                    peer_key: public_key.as_ref().to_vec(),
                    message: contents.into(),
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
        pub fn run(mut self) -> EventStream {
            let options = self.options.clone();
            let server = self.server.clone();
            let peers = self.peers.clone();

            let s = stream! {
                loop {
                    tokio::select!(
                        biased;
                        Some(message_out) = self.outbound_rx.recv() => {
                            match message_out {
                                InternalMessage::Request(request) => {
                                    if let Err(e) = self.send_message(request).await {
                                        tracing::warn!(error = %e);
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
                        },
                        Some(message_in) = self.ws_reader.next() => {
                            match message_in {
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
                        },
                        Some(event_message) = self.inbound_rx.recv() => {
                            match Self::handle_incoming_message(
                                options.clone(),
                                server.clone(),
                                peers.clone(),
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
                        },
                    );
                }
            };
            Box::pin(s)
        }
    }
}

pub(crate) use event_loop_run_impl;
