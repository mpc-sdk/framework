use async_stream::stream;
use futures::{
    select,
    sink::SinkExt,
    stream::{BoxStream, SplitSink, SplitStream},
    FutureExt, StreamExt,
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    net::TcpStream,
    sync::{mpsc, Mutex, RwLock},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};

use mpc_relay_protocol::{
    channel::{decrypt_server_channel, encrypt_server_channel},
    decode, encode, hex,
    http::StatusCode,
    snow::Builder,
    Encoding, HandshakeType, PeerMessage, ProtocolState,
    RequestMessage, ResponseMessage, SealedEnvelope, SessionId,
    SessionRequest, SessionResponse, PATTERN, TAGLEN,
};

use crate::{ClientOptions, Error, Event, JsonMessage, Result};

type Peers = Arc<RwLock<HashMap<Vec<u8>, ProtocolState>>>;
type Server = Arc<RwLock<Option<ProtocolState>>>;

/// Notifications sent from the event loop to the client.
#[derive(Debug)]
#[doc(hidden)]
pub enum Notification {
    /// Notification sent when the server handshake is complete.
    ServerHandshake,
}

/// Native websocket client using the tokio tungstenite library.
#[derive(Clone)]
pub struct NativeClient {
    options: Arc<ClientOptions>,
    notification_rx: Arc<Mutex<mpsc::Receiver<Notification>>>,
    outbound_tx: mpsc::Sender<RequestMessage>,
    server: Server,
    peers: Peers,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new<R>(
        request: R,
        options: ClientOptions,
    ) -> Result<(Self, EventLoop)>
    where
        R: IntoClientRequest + Unpin,
    {
        let (stream, response) = connect_async(request).await?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::HttpError(
                response.status(),
                response.status().to_string(),
            ));
        }

        let (ws_writer, ws_reader) = stream.split();

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&options.keypair.private)
            .remote_public_key(&options.server_public_key)
            .build_initiator()?;

        // Channel for writing outbound messages to send
        // to the server
        let (outbound_tx, outbound_rx) =
            mpsc::channel::<RequestMessage>(32);

        // Internal notification bridge between the client and
        // the event loop
        let (notification_tx, notification_rx) =
            mpsc::channel::<Notification>(32);

        // State for the server transport
        let server = Arc::new(RwLock::new(Some(
            ProtocolState::Handshake(handshake),
        )));

        let peers = Arc::new(RwLock::new(Default::default()));
        let options = Arc::new(options);
        let client = Self {
            options: Arc::clone(&options),
            notification_rx: Arc::new(Mutex::new(notification_rx)),
            outbound_tx: outbound_tx.clone(),
            server: Arc::clone(&server),
            peers: Arc::clone(&peers),
        };

        // Decoded socket messages are sent over this channel
        let (message_tx, message_rx) =
            mpsc::channel::<ResponseMessage>(32);

        let event_loop = EventLoop {
            options,
            ws_reader,
            ws_writer,
            message_tx,
            message_rx,
            outbound_tx,
            outbound_rx,
            notification_tx,
            server,
            peers,
        };

        Ok((client, event_loop))
    }

    /// The public key for this client.
    pub fn public_key(&self) -> &[u8] {
        &self.options.keypair.public
    }

    /// Perform initial handshake with the server.
    pub async fn connect(&mut self) -> Result<()> {
        let request = {
            let mut state = self.server.write().await;

            let (len, payload) = match &mut *state {
                Some(ProtocolState::Handshake(initiator)) => {
                    let mut request = vec![0u8; 1024];
                    let len =
                        initiator.write_message(&[], &mut request)?;
                    (len, request)
                }
                _ => return Err(Error::NotHandshakeState),
            };

            RequestMessage::HandshakeInitiator(
                HandshakeType::Server,
                len,
                payload,
            )
        };

        self.outbound_tx.send(request).await?;

        Ok(())
    }

    /// Handshake with a peer.
    ///
    /// Peer already exists error is returned if this
    /// client is already connecting to the peer.
    pub async fn connect_peer(
        &mut self,
        public_key: impl AsRef<[u8]>,
    ) -> Result<()> {
        let mut peers = self.peers.write().await;

        if peers.get(public_key.as_ref()).is_some() {
            return Err(Error::PeerAlreadyExists);
        }

        tracing::debug!(
            to = ?hex::encode(public_key.as_ref()),
            "peer handshake initiator"
        );

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&self.options.keypair.private)
            .remote_public_key(public_key.as_ref())
            .build_initiator()?;
        let peer_state = ProtocolState::Handshake(handshake);

        let state = peers
            .entry(public_key.as_ref().to_vec())
            .or_insert(peer_state);

        let (len, payload) = match state {
            ProtocolState::Handshake(initiator) => {
                let mut request = vec![0u8; 1024];
                let len =
                    initiator.write_message(&[], &mut request)?;
                (len, request)
            }
            _ => return Err(Error::NotHandshakeState),
        };
        drop(peers);

        let inner_request: PeerMessage =
            RequestMessage::HandshakeInitiator(
                HandshakeType::Peer,
                len,
                payload,
            )
            .into();
        let inner_message = encode(&inner_request).await?;

        let request = RequestMessage::RelayPeer {
            handshake: true,
            public_key: public_key.as_ref().to_vec(),
            message: inner_message,
            session_id: None,
        };

        self.outbound_tx.send(request).await?;

        Ok(())
    }

    /// Try to connect to a peer.
    ///
    /// If the peer already exists the error is ignored
    /// and this method will return `false`.
    ///
    /// Use this when peers need to race to connect to
    /// each other.
    pub async fn try_connect_peer(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<bool> {
        if let Err(e) = self.connect_peer(key).await {
            match e {
                Error::PeerAlreadyExists => {
                    return Ok(false);
                }
                _ => return Err(e.into()),
            }
        }
        Ok(true)
    }

    /// Encode as JSON and relay to the peer.
    pub async fn send<S>(
        &mut self,
        public_key: impl AsRef<[u8]>,
        payload: &S,
    ) -> Result<()>
    where
        S: Serialize + ?Sized,
    {
        self.relay(
            public_key,
            &serde_json::to_vec(payload)?,
            Encoding::Json,
            false,
            None,
        )
        .await
    }

    /// Encode as binary and relay to the peer.
    pub async fn send_binary(
        &mut self,
        public_key: impl AsRef<[u8]>,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.relay(public_key, &payload, Encoding::Blob, false, None)
            .await
    }

    /// Relay a buffer to a peer over the noise protocol channel.
    ///
    /// The peers must have already performed the noise protocol
    /// handshake.
    async fn relay(
        &mut self,
        public_key: impl AsRef<[u8]>,
        payload: &[u8],
        encoding: Encoding,
        broadcast: bool,
        session_id: Option<SessionId>,
    ) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(public_key.as_ref()) {
            let request = encrypt_peer_channel(
                public_key, peer, payload, encoding, broadcast,
                session_id,
            )
            .await?;
            self.outbound_tx.send(request).await?;
            Ok(())
        } else {
            Err(Error::PeerNotFound(hex::encode(
                public_key.as_ref().to_vec(),
            )))
        }
    }

    /// Create a new session.
    pub async fn new_session(
        &mut self,
        participant_keys: Vec<Vec<u8>>,
    ) -> Result<()> {
        let session = SessionRequest { participant_keys };
        let message = RequestMessage::NewSession(session);
        self.request(message).await
    }

    /// Request to be notified when all session participants are ready.
    ///
    /// Sends a request to the server to check whether all participants
    /// have completed their server handshake.
    ///
    /// When the server detects all participants are connected a session
    /// ready notification is sent to all the peers.
    ///
    /// Once peers receive the session ready notification they can
    /// race to connect to each other.
    pub async fn session_ready_notify(
        &mut self,
        session_id: &SessionId,
    ) -> Result<()> {
        self.request(RequestMessage::SessionReadyNotify(*session_id))
            .await
    }

    /// Request to be notified when a session is active.
    ///
    /// A session is active when all of the participants in a session
    /// have established peer connections.
    pub async fn session_active_notify(
        &mut self,
        session_id: &SessionId,
    ) -> Result<()> {
        self.request(RequestMessage::SessionActiveNotify(*session_id))
            .await
    }

    /// Register a peer connection in a session.
    pub async fn register_session_connection(
        &mut self,
        session_id: &SessionId,
        peer_key: &Vec<u8>,
    ) -> Result<()> {
        let message = RequestMessage::SessionConnection {
            session_id: *session_id,
            peer_key: peer_key.to_vec(),
        };
        self.request(message).await
    }

    /// Encrypt a request message and send over the encrypted
    /// server channel.
    async fn request(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let inner = {
            let mut server = self.server.write().await;
            if let Some(server) = server.as_mut() {
                let payload = encode(&message).await?;
                let inner =
                    encrypt_server_channel(server, payload, false)
                        .await?;
                Some(inner)
            } else {
                None
            }
        };

        if let Some(inner) = inner {
            let request = RequestMessage::Envelope(inner);
            self.outbound_tx.send(request).await?;
            Ok(())
        } else {
            unreachable!()
        }
    }

    /// Broadcast JSON in the context of a session.
    pub async fn broadcast<S>(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: Vec<Vec<u8>>,
        payload: &S,
    ) -> Result<()>
    where
        S: Serialize + ?Sized,
    {
        self.relay_broadcast(
            session_id,
            recipient_public_keys,
            serde_json::to_vec(payload)?,
            Encoding::Json,
        )
        .await
    }

    /// Broadcast as binary in the context of a session.
    pub async fn broadcast_binary(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: Vec<Vec<u8>>,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.relay_broadcast(
            session_id,
            recipient_public_keys,
            payload,
            Encoding::Blob,
        )
        .await
    }

    async fn relay_broadcast(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: Vec<Vec<u8>>,
        payload: Vec<u8>,
        encoding: Encoding,
    ) -> Result<()> {
        for key in recipient_public_keys {
            self.relay(
                key,
                &payload,
                encoding,
                true,
                Some(*session_id),
            )
            .await?;
        }
        Ok(())
    }
}

/// Event loop for a websocket client.
pub struct EventLoop {
    options: Arc<ClientOptions>,
    ws_reader:
        SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ws_writer: SplitSink<
        WebSocketStream<MaybeTlsStream<TcpStream>>,
        Message,
    >,
    message_tx: mpsc::Sender<ResponseMessage>,
    message_rx: mpsc::Receiver<ResponseMessage>,
    outbound_tx: mpsc::Sender<RequestMessage>,
    outbound_rx: mpsc::Receiver<RequestMessage>,
    notification_tx: mpsc::Sender<Notification>,
    server: Server,
    peers: Peers,
}

impl EventLoop {
    /// Stream of events from the event loop.
    pub fn run<'a>(&'a mut self) -> BoxStream<'a, Result<Event>> {
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
                                        &mut self.message_tx,
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
                            if let Err(e) = self.send_message(message).await {
                                yield Err(e)
                            }
                        }
                        _ => {}
                    },
                    event_message =
                        self.message_rx.recv().fuse()
                            => match event_message {
                        Some(event_message) => {
                            match self.handle_incoming_message(
                                event_message).await {

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

    /// Send a message to the socket and flush the stream.
    async fn send_message(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let message = Message::Binary(encode(&message).await?);
        self.ws_writer.send(message).await?;
        Ok(self.ws_writer.flush().await?)
    }

    /// Receive and decode socket messages then send to
    /// the messages channel.
    async fn read_message(
        incoming: Message,
        event_loop: &mut mpsc::Sender<ResponseMessage>,
    ) -> Result<()> {
        if let Message::Binary(buffer) = incoming {
            let response: ResponseMessage = decode(buffer).await?;
            event_loop.send(response).await?;
        }
        Ok(())
    }

    async fn handle_incoming_message(
        &mut self,
        incoming: ResponseMessage,
    ) -> Result<Option<Event>> {
        match incoming {
            ResponseMessage::Error(code, message) => {
                Err(Error::HttpError(code, message))
            }
            ResponseMessage::HandshakeResponder(
                HandshakeType::Server,
                len,
                buf,
            ) => Ok(Some(self.server_handshake(len, buf).await?)),
            ResponseMessage::RelayPeer {
                handshake,
                public_key,
                message,
            } => {
                if handshake {
                    // Decode the inner message
                    let relayed =
                        decode::<PeerMessage>(message).await?;
                    match relayed {
                        PeerMessage::Request(
                            RequestMessage::HandshakeInitiator(
                                HandshakeType::Peer,
                                len,
                                buf,
                            ),
                        ) => Ok(self
                            .peer_handshake_responder(
                                public_key, len, buf,
                            )
                            .await?),
                        PeerMessage::Response(
                            ResponseMessage::HandshakeResponder(
                                HandshakeType::Peer,
                                len,
                                buf,
                            ),
                        ) => Ok(Some(
                            self.peer_handshake_ack(
                                public_key, len, buf,
                            )
                            .await?,
                        )),
                        _ => Err(Error::InvalidPeerHandshakeMessage),
                    }
                } else {
                    Ok(Some(
                        self.handle_relayed_message(
                            public_key, message,
                        )
                        .await?,
                    ))
                }
            }
            ResponseMessage::Envelope(message) => {
                let mut server = self.server.write().await;
                if let Some(server) = server.as_mut() {
                    let (encoding, contents) =
                        decrypt_server_channel(server, message)
                            .await?;
                    let message = match encoding {
                        Encoding::Blob => {
                            let response: ResponseMessage =
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
                //Ok(None)
            }
        }
    }

    /// Process an inner message from the server after
    /// decrypting the envelope.
    async fn handle_server_channel_message(
        &self,
        message: ResponseMessage,
    ) -> Result<Option<Event>> {
        match message {
            ResponseMessage::Error(code, message) => {
                eprintln!("{} {}", code, message);
                Ok(None)
            }
            ResponseMessage::SessionCreated(response) => {
                Ok(Some(Event::SessionCreated(response)))
            }
            ResponseMessage::SessionReady(response) => {
                Ok(Some(Event::SessionReady(response)))
            }
            ResponseMessage::SessionActive(response) => {
                Ok(Some(Event::SessionActive(response)))
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

        self.notification_tx
            .send(Notification::ServerHandshake)
            .await?;

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

        if peers.get(public_key.as_ref()).is_none() {
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

            let inner_request: PeerMessage =
                ResponseMessage::HandshakeResponder(
                    HandshakeType::Peer,
                    len,
                    payload,
                )
                .into();
            let inner_message = encode(&inner_request).await?;

            let request = RequestMessage::RelayPeer {
                handshake: true,
                public_key: public_key.as_ref().to_vec(),
                message: inner_message,
                session_id: None,
            };

            self.outbound_tx.send(request).await?;

            Ok(Some(Event::PeerConnected {
                peer_key: public_key.as_ref().to_vec(),
            }))
        } else {
            Ok(None)
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
        payload: Vec<u8>,
    ) -> Result<Event> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(public_key.as_ref()) {
            let (envelope, contents) =
                decrypt_peer_channel(peer, payload).await?;
            match envelope.encoding {
                Encoding::Noop => unreachable!(),
                Encoding::Blob => Ok(Event::BinaryMessage {
                    peer_key: public_key.as_ref().to_vec(),
                    message: contents,
                }),
                Encoding::Json => Ok(Event::JsonMessage {
                    peer_key: public_key.as_ref().to_vec(),
                    message: JsonMessage { contents },
                }),
            }
        } else {
            Err(Error::PeerNotFound(hex::encode(
                public_key.as_ref().to_vec(),
            )))
        }
    }
}

/// Encrypt a message to send to a peer.
///
/// The protocol must be in transport mode.
async fn encrypt_peer_channel(
    public_key: impl AsRef<[u8]>,
    peer: &mut ProtocolState,
    payload: &[u8],
    encoding: Encoding,
    broadcast: bool,
    session_id: Option<SessionId>,
) -> Result<RequestMessage> {
    match peer {
        ProtocolState::Transport(transport) => {
            let mut contents = vec![0; payload.len() + TAGLEN];
            let length =
                transport.write_message(payload, &mut contents)?;
            let envelope = SealedEnvelope {
                length,
                encoding,
                payload: contents,
                broadcast,
            };
            let message = encode(&envelope).await?;
            let request = RequestMessage::RelayPeer {
                handshake: false,
                public_key: public_key.as_ref().to_vec(),
                message,
                session_id,
            };
            Ok(request)
        }
        _ => Err(Error::NotTransportState),
    }
}

/// Decrypt a message received from a peer.
///
/// The protocol must be in transport mode.
async fn decrypt_peer_channel(
    peer: &mut ProtocolState,
    payload: Vec<u8>,
) -> Result<(SealedEnvelope, Vec<u8>)> {
    match peer {
        ProtocolState::Transport(transport) => {
            let envelope: SealedEnvelope = decode(&payload).await?;
            let mut contents = vec![0; envelope.length];
            transport.read_message(
                &envelope.payload[..envelope.length],
                &mut contents,
            )?;
            let new_length = contents.len() - TAGLEN;
            contents.truncate(new_length);
            Ok((envelope, contents))
        }
        _ => Err(Error::NotTransportState),
    }
}
