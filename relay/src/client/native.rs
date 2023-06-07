use futures::{
    select,
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    FutureExt, StreamExt,
};
use snow::{Builder, Keypair};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    net::TcpStream,
    runtime::Handle,
    sync::{mpsc, Mutex, RwLock},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest, handshake::client::Response,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use crate::{
    constants::PATTERN, decode, encode, ClientOptions, Error,
    HandshakeType, PeerMessage, ProtocolState, RequestMessage,
    ResponseMessage, Result,
};

type Peers = Arc<RwLock<HashMap<Vec<u8>, ProtocolState>>>;

pub struct EventLoop {
    socket: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    event_loop_tx: mpsc::Sender<ResponseMessage>,
    event_loop_rx: mpsc::Receiver<ResponseMessage>,
    server_handshake: mpsc::Sender<ResponseMessage>,
    public_key_id: String,
}

impl EventLoop {
    /// Start the client event loop running.
    pub async fn run(mut self) {
        loop {
            select!(
                socket_message = self.socket.next().fuse() => match socket_message {
                    Some(socket_message) => {
                        match socket_message {
                            Ok(message) => {
                                Self::process_socket_message(
                                    message,
                                    &mut self.event_loop_tx,
                                    &mut self.server_handshake,
                                ).await;
                            }
                            Err(e) => {
                                tracing::error!("{}", e);
                            }
                        }
                    }
                    _ => {}
                },
                event_message = self.event_loop_rx.recv().fuse() => match event_message {
                    Some(event_message) => {
                        Self::process_incoming_message(event_message).await;
                    }
                    _ => {}
                },
            );
        }
    }

    async fn process_incoming_message(incoming: ResponseMessage) {
        println!("process_incoming_message");
        match incoming {
            ResponseMessage::Error(code, message) => {
                tracing::error!("{} {}", code, message);
            }
            ResponseMessage::RelayPeer {
                public_key,
                message,
            } => {
                println!("client got relay peer input...");
                // Decode the inner message
                match decode::<PeerMessage>(message).await {
                    Ok(relayed) => match relayed {
                        PeerMessage::Request(
                            RequestMessage::HandshakeInitiator(
                                HandshakeType::Peer,
                                len,
                                buf,
                            ),
                        ) => {
                            println!("got peer handshake initiator message to process");
                        }
                        _ => todo!(),
                    },
                    Err(e) => {
                        tracing::error!(
                            "client decode inner message error {}",
                            e
                        );
                    }
                }
            }
            _ => {}
        }
    }

    /// Decode socket messages and send to the appropriate channel.
    async fn process_socket_message(
        incoming: Message,
        event_loop: &mut mpsc::Sender<ResponseMessage>,
        server_handshake: &mut mpsc::Sender<ResponseMessage>,
    ) {
        let buffer = incoming.into_data();
        println!("process_socket_message {}", buffer.len());
        match decode::<ResponseMessage>(buffer).await {
            Ok(response) => match response {
                ResponseMessage::HandshakeResponder(
                    HandshakeType::Server,
                    _,
                    _,
                ) => {
                    println!("Sending to server handshake..");
                    let _ = server_handshake.send(response).await;
                }
                _ => {
                    println!("sending to event loop...");
                    let _ = event_loop.send(response).await;
                }
            },
            Err(e) => {
                tracing::error!("client decode message error {}", e);
            }
        }
    }
}

/// Native websocket client using the tokio tungstenite library.
pub struct NativeClient {
    options: ClientOptions,
    writer: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    server_handshake: mpsc::Receiver<ResponseMessage>,
    response: Response,
    state: Option<ProtocolState>,
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
        let (ws_writer, mut ws_reader) = stream.split();

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&options.keypair.private)
            .remote_public_key(&options.server_public_key)
            .build_initiator()?;

        let (event_sender, mut event_reader) =
            mpsc::channel::<ResponseMessage>(32);
        let (server_handshake_tx, server_handshake) =
            mpsc::channel::<ResponseMessage>(32);

        //let (server_handshake_tx, server_handshake) =
            //mpsc::channel::<ResponseMessage>(32);

        let peers = Arc::new(RwLock::new(Default::default()));
        let public_key_id = hex::encode(&options.keypair.public);

        //let event_loop_peers = Arc::clone(&peers);

        // Start the client event loop.
        let event_loop = EventLoop {
            socket: ws_reader,
            event_loop_tx: event_sender,
            event_loop_rx: event_reader,
            server_handshake: server_handshake_tx,
            public_key_id,
        };

        let mut client = Self {
            options,
            writer: ws_writer,
            server_handshake,
            response,
            state: Some(ProtocolState::Handshake(handshake)),
            peers,
        };

        Ok((client, event_loop))
    }

    /// Perform initial handshake with the server.
    pub async fn handshake(&mut self) -> Result<()> {
        let (len, payload) = match &mut self.state {
            Some(ProtocolState::Handshake(initiator)) => {
                let mut request = vec![0u8; 1024];
                let len = initiator.write_message(&[], &mut request)?;
                (len, request)
            }
            _ => return Err(Error::NotHandshakeState),
        };

        let request = RequestMessage::HandshakeInitiator(
            HandshakeType::Server,
            len,
            payload,
        );
        self.send_request(request).await?;

        while let Some(response) = self.server_handshake.recv().await {
            let transport = match self.state.take() {
                Some(ProtocolState::Handshake(mut initiator)) => {
                    match response {
                        ResponseMessage::HandshakeResponder(
                            HandshakeType::Server,
                            len,
                            buf,
                        ) => {
                            let mut read_buf = vec![0u8; 1024];
                            initiator.read_message(
                                &buf[..len],
                                &mut read_buf,
                            )?;

                            initiator.into_transport_mode()?
                        }
                        _ => return Err(Error::NotHandshakeReply),
                    }
                }
                _ => return Err(Error::NotHandshakeState),
            };

            self.state = Some(ProtocolState::Transport(transport));

            break;
        }
        Ok(())
    }

    /// Handshake with a peer.
    pub async fn connect_peer(
        &mut self,
        public_key: impl AsRef<[u8]>,
    ) -> Result<()> {
        let mut peers = self.peers.write().await;

        if peers.get(public_key.as_ref()).is_some() {
            return Err(Error::PeerAlreadyExists);
        }

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
                let len = initiator.write_message(&[], &mut request)?;
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
            public_key: public_key.as_ref().to_vec(),
            message: inner_message,
        };

        self.send_request(request).await
    }

    /// Send a request message.
    async fn send_request(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let buffer = encode(&message).await?;
        self.send_binary(buffer).await
    }

    /// Send a binary message to the server.
    async fn send_binary(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.send_socket(Message::Binary(buffer)).await
    }

    /// Send a message to the socket and flush the stream.
    async fn send_socket(&mut self, message: Message) -> Result<()> {
        self.writer.send(message).await?;
        Ok(self.writer.flush().await?)
    }
}
