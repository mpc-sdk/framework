use async_stream::stream;
use futures::{
    select,
    sink::SinkExt,
    stream::{BoxStream, SplitSink, SplitStream},
    FutureExt, StreamExt,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Message},
    MaybeTlsStream, WebSocketStream,
};

use mpc_relay_protocol::{
    channel::encrypt_server_channel, decode, encode, hex,
    http::StatusCode, snow::Builder, Encoding, HandshakeMessage,
    OpaqueMessage, ProtocolState, RequestMessage, ResponseMessage,
    ServerMessage, SessionId, SessionRequest, TransparentMessage,
    PATTERN,
};

use super::{
    encrypt_peer_channel, event_loop::EventLoop, Peers, Server,
};
use crate::{ClientOptions, Error, Event, Result};

type WsMessage = Message;
type WsError = tokio_tungstenite::tungstenite::Error;
type WsReadStream =
    SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
type WsWriteStream =
    SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

/// Event loop for the native client.
pub type NativeEventLoop =
    EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream>;

/// Native websocket client using the tokio tungstenite library.
#[derive(Clone)]
pub struct NativeClient {
    options: Arc<ClientOptions>,
    outbound_tx: mpsc::Sender<RequestMessage>,
    server: Server,
    peers: Peers,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new<R>(
        server: R,
        options: ClientOptions,
    ) -> Result<(Self, NativeEventLoop)>
    where
        R: IntoClientRequest + Unpin,
    {
        let (stream, response) = connect_async(server).await?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::ConnectError(
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

        // State for the server transport
        let server = Arc::new(RwLock::new(Some(
            ProtocolState::Handshake(Box::new(handshake)),
        )));

        let peers = Arc::new(RwLock::new(Default::default()));
        let options = Arc::new(options);
        let client = Self {
            options: Arc::clone(&options),
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
            server,
            peers,
            builder: Box::new(|message| {
                Box::pin(async move {
                    let message =
                        Message::Binary(encode(&message).await?);
                    Ok(message)
                })
            }),
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

            RequestMessage::Transparent(
                TransparentMessage::ServerHandshake(
                    HandshakeMessage::Initiator(len, payload),
                ),
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
        let peer_state =
            ProtocolState::Handshake(Box::new(handshake));

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

        let request = RequestMessage::Transparent(
            TransparentMessage::PeerHandshake {
                public_key: public_key.as_ref().to_vec(),
                message: HandshakeMessage::Initiator(len, payload),
            },
        );

        self.outbound_tx.send(request).await?;

        Ok(())
    }

    /// Send a JSON message to a peer via the relay service.
    pub async fn send<S>(
        &mut self,
        public_key: impl AsRef<[u8]>,
        payload: &S,
        session_id: Option<SessionId>,
    ) -> Result<()>
    where
        S: Serialize + ?Sized,
    {
        self.relay(
            public_key,
            &serde_json::to_vec(payload)?,
            Encoding::Json,
            false,
            session_id,
        )
        .await
    }

    /// Send a binary message to a peer via the relay service.
    pub async fn send_blob(
        &mut self,
        public_key: impl AsRef<[u8]>,
        payload: Vec<u8>,
        session_id: Option<SessionId>,
    ) -> Result<()> {
        self.relay(
            public_key,
            &payload,
            Encoding::Blob,
            false,
            session_id,
        )
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
        let message = ServerMessage::NewSession(session);
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
    /// connect to each other.
    pub async fn session_ready_notify(
        &mut self,
        session_id: &SessionId,
    ) -> Result<()> {
        self.request(ServerMessage::SessionReadyNotify(*session_id))
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
        self.request(ServerMessage::SessionActiveNotify(*session_id))
            .await
    }

    /// Register a peer connection in a session.
    pub async fn register_session_connection(
        &mut self,
        session_id: &SessionId,
        peer_key: &[u8],
    ) -> Result<()> {
        let message = ServerMessage::SessionConnection {
            session_id: *session_id,
            peer_key: peer_key.to_vec(),
        };
        self.request(message).await
    }

    /// Close a session.
    pub async fn close_session(
        &mut self,
        session_id: SessionId,
    ) -> Result<()> {
        let message = ServerMessage::CloseSession(session_id);
        self.request(message).await
    }

    /// Encrypt a request message and send over the encrypted
    /// server channel.
    async fn request(
        &mut self,
        message: ServerMessage,
    ) -> Result<()> {
        let envelope = {
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

        if let Some(envelope) = envelope {
            let request = RequestMessage::Opaque(
                OpaqueMessage::ServerMessage(envelope),
            );
            self.outbound_tx.send(request).await?;
            Ok(())
        } else {
            unreachable!()
        }
    }

    /// Broadcast a JSON message in the context of a session.
    pub async fn broadcast<S>(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: &[Vec<u8>],
        payload: &S,
    ) -> Result<()>
    where
        S: Serialize + ?Sized,
    {
        self.relay_broadcast(
            session_id,
            recipient_public_keys,
            &serde_json::to_vec(payload)?,
            Encoding::Json,
        )
        .await
    }

    /// Broadcast a binary message in the context of a session.
    pub async fn broadcast_blob(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: &[Vec<u8>],
        payload: Vec<u8>,
    ) -> Result<()> {
        self.relay_broadcast(
            session_id,
            recipient_public_keys,
            &payload,
            Encoding::Blob,
        )
        .await
    }

    async fn relay_broadcast(
        &mut self,
        session_id: &SessionId,
        recipient_public_keys: &[Vec<u8>],
        payload: &[u8],
        encoding: Encoding,
    ) -> Result<()> {
        for key in recipient_public_keys {
            self.relay(
                key,
                payload,
                encoding,
                true,
                Some(*session_id),
            )
            .await?;
        }
        Ok(())
    }
}

impl EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream> {
    /// Receive and decode socket messages then send to
    /// the messages channel.
    pub(crate) async fn read_message(
        incoming: Message,
        event_loop: &mut mpsc::Sender<ResponseMessage>,
    ) -> Result<()> {
        if let Message::Binary(buffer) = incoming {
            let response: ResponseMessage = decode(buffer).await?;
            event_loop.send(response).await?;
        }
        Ok(())
    }

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
}
