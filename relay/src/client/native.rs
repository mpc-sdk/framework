use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use snow::{Builder, Keypair};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    net::TcpStream,
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
    HandshakeType, ProtocolState, RequestMessage, ResponseMessage, Result,
};

type Peers = Arc<RwLock<HashMap<Vec<u8>, ProtocolState>>>;

/// Native websocket client using the tokio tungstenite library.
pub struct NativeClient {
    options: ClientOptions,
    writer: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    server_handshake: mpsc::Receiver<ResponseMessage>,
    response: Response,
    state: ProtocolState,
    peers: Peers,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new<R>(request: R, options: ClientOptions) -> Result<Self>
    where
        R: IntoClientRequest + Unpin,
    {
        let (stream, response) = connect_async(request).await?;
        let (ws_writer, ws_reader) = stream.split();

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&options.keypair.private)
            .remote_public_key(&options.server_public_key)
            .build_initiator()?;

        let (event_sender, mut event_reader) =
            mpsc::channel::<ResponseMessage>(32);
        let (server_handshake_tx, server_handshake) =
            mpsc::channel::<ResponseMessage>(32);

        let auto_handshake = options.auto_handshake;

        let peers = Arc::new(RwLock::new(Default::default()));
        let public_key_id = hex::encode(&options.keypair.public);
        
        // Handle incoming buffers and convert them to response messages
        tokio::spawn(read_incoming_message(
            ws_reader,
            event_sender,
            server_handshake_tx,
            public_key_id,
        ));

        let event_loop_peers = Arc::clone(&peers);
        
        let mut client = Self {
            options,
            writer: ws_writer,
            server_handshake,
            response,
            state: ProtocolState::Handshake(handshake),
            peers,
        };

        if auto_handshake {
            client = client.handshake().await?;
        }

        // Handle the decoded response messages
        tokio::spawn(event_loop(event_reader, event_loop_peers));

        Ok(client)
    }

    /// Perform initial handshake with the server.
    pub async fn handshake(mut self) -> Result<Self> {
        let (len, payload) = match &mut self.state {
            ProtocolState::Handshake(initiator) => {
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
            match self.state {
                ProtocolState::Handshake(mut initiator) => match response {
                    ResponseMessage::HandshakeResponder(
                        HandshakeType::Server,
                        len,
                        buf,
                    ) => {
                        let mut read_buf = vec![0u8; 1024];
                        initiator.read_message(&buf[..len], &mut read_buf)?;

                        let transport = initiator.into_transport_mode()?;
                        self.state = ProtocolState::Transport(transport);
                    }
                    _ => return Err(Error::NotHandshakeReply),
                },
                _ => return Err(Error::NotHandshakeState),
            }
            break;
        }
        Ok(self)
    }

    /// Initiate handshake with a peer.
    pub async fn peer_handshake(
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

        let inner_request = RequestMessage::HandshakeInitiator(
            HandshakeType::Peer,
            len,
            payload,
        );
        let inner_message = encode(&inner_request).await?;

        let request = RequestMessage::RelayPeer {
            public_key: public_key.as_ref().to_vec(),
            message: inner_message,
        };

        self.send_request(request).await
    }

    fn read_response_message(
        response: ResponseMessage,
    ) -> Result<ResponseMessage> {
        //let response =
        //reader.recv().await.ok_or_else(|| Error::NoReply)?;
        match response {
            ResponseMessage::Error(code, message) => {
                Err(Error::ServerError(code, message))
            }
            _ => Ok(response),
        }
    }

    /// Send a request message.
    async fn send(&mut self, message: RequestMessage) -> Result<()> {
        let buffer = encode(&message).await?;
        self.send_binary(buffer).await
    }

    /// Send a request message and expect a response.
    async fn send_request(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let buffer = encode(&message).await?;
        self.send_binary(buffer).await?;
        Ok(())

        /*
        if let Some(reader) = self.reader.as_mut() {
            let response =
                reader.recv().await.ok_or_else(|| Error::NoReply)?;
            match response {
                ResponseMessage::Error(code, message) => {
                    Err(Error::ServerError(code, message))
                }
                _ => Ok(response),
            }
        } else {
            panic!("reader loop already started");
        }
        */
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

async fn event_loop(
    mut event_reader: mpsc::Receiver<ResponseMessage>,
    peers: Peers,
) -> Result<()> {
    println!("starting the event loop...");
    while let Some(message) = event_reader.recv().await {
        println!("got incoming message...");
    }
    Ok::<(), crate::Error>(())
}

async fn read_incoming_message(
    mut incoming: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    event_loop: mpsc::Sender<ResponseMessage>,
    server_handshake: mpsc::Sender<ResponseMessage>,
    public_key_id: String,
) -> Result<()> {
    println!("starting client read loop {}", public_key_id);

    while let Some(reply) = incoming.next().await {
        println!("client received message!!");
        //println!("{} received message in client", public_key_id);
        match reply {
            Ok(message) => {
                let buffer = message.into_data();
                match decode::<ResponseMessage>(buffer).await {
                    Ok(response) => {
                        match response {
                            ResponseMessage::HandshakeResponder(HandshakeType::Server, _, _) => {
                                server_handshake
                                    .send(response)
                                    .await?;
                            }
                            ResponseMessage::RelayPeer {
                                public_key,
                                message,
                            } => {
                                println!(
                                    "client got relay peer input..."
                                );
                                // Decode the inner message
                                match decode::<ResponseMessage>(
                                    message,
                                )
                                .await
                                {
                                    Ok(relayed) => {
                                        event_loop
                                            .send(relayed)
                                            .await?;
                                    }
                                    Err(e) => {
                                        tracing::error!("client decode inner message error {}", e);
                                    }
                                }
                            }
                            /*
                            ResponseMessage::HandshakeResponder(HandshakeType::Peer, len, buf) => {
                                println!("got peer handshake responder message to process");
                            }
                            */
                            _ => {
                                event_loop.send(response).await?;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "client decode message error {}",
                            e
                        );
                    }
                }
            },
            Err(e) => tracing::error!("{}", e),
        }
    }
    Ok(())
}
