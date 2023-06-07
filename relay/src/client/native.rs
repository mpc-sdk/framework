use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use snow::{Builder, Keypair};
use std::{collections::HashMap, sync::Arc};
use tokio::{net::TcpStream, sync::{mpsc, RwLock}};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest, handshake::client::Response,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use crate::{
    constants::PATTERN, decode, encode, Error, ProtocolState,
    RequestMessage, ResponseMessage, Result, ClientOptions, HandshakeType,
};

type Peers = Arc<RwLock<HashMap<Vec<u8>, ProtocolState>>>;

/// Native websocket client using the tokio tungstenite library.
pub struct NativeClient {
    options: ClientOptions,
    writer: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    reader: mpsc::Receiver<ResponseMessage>,
    response: Response,
    state: ProtocolState,
    peers: Peers,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new<R>(
        request: R,
        options: ClientOptions,
    ) -> Result<Self>
    where
        R: IntoClientRequest + Unpin,
    {
        let (stream, response) = connect_async(request).await?;
        let (writer, read) = stream.split();

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&options.keypair.private)
            .remote_public_key(&options.server_public_key)
            .build_initiator()?;

        let (sender, reader) = mpsc::channel::<ResponseMessage>(32);

        let auto_handshake = options.auto_handshake;
        
        let peers = Arc::new(RwLock::new(Default::default()));
        let public_key_id = hex::encode(&options.keypair.public);
        tokio::spawn(read_incoming_message(read, sender, public_key_id, Arc::clone(&peers)));

        let mut client = Self {
            options,
            writer,
            reader,
            response,
            state: ProtocolState::Handshake(handshake),
            peers,
        };

        if auto_handshake {
            client = client.handshake().await?;
        }
        
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

        let request = RequestMessage::HandshakeInitiator(HandshakeType::Server, len, payload);
        let response = self.request(request).await?;

        match self.state {
            ProtocolState::Handshake(mut initiator) => match response {
                ResponseMessage::HandshakeResponder(HandshakeType::Server, len, buf) => {
                    let mut read_buf = vec![0u8; 1024];
                    initiator.read_message(&buf[..len], &mut read_buf)?;

                    let transport = initiator.into_transport_mode()?;
                    self.state = ProtocolState::Transport(transport);

                    Ok(self)
                }
                _ => return Err(Error::NotHandshakeReply),
            },
            _ => return Err(Error::NotHandshakeState),
        }
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

        let inner_request =
            RequestMessage::HandshakeInitiator(HandshakeType::Peer, len, payload);
        let inner_message = encode(&inner_request).await?;

        println!("encoding outer relay peer message {}", hex::encode(public_key.as_ref()));

        let request = RequestMessage::RelayPeer {
            public_key: public_key.as_ref().to_vec(),
            message: inner_message,
        };

        self.send(request).await

        //let inner_request =

        /*
        let (len, payload) = match &mut self.state {
            ProtocolState::Handshake(initiator) => {
                let mut request = vec![0u8; 1024];
                let len = initiator.write_message(&[], &mut request)?;
                (len, request)
            }
            _ => return Err(Error::NotHandshakeState),
        };

        let request = RequestMessage::HandshakeInitiator(len, payload);
        let response = self.request(request).await?;

        match self.state {
            ProtocolState::Handshake(mut initiator) => match response {
                ResponseMessage::HandshakeResponder(len, buf) => {
                    let mut read_buf = vec![0u8; 1024];
                    initiator.read_message(&buf[..len], &mut read_buf)?;

                    let transport = initiator.into_transport_mode()?;
                    self.state = ProtocolState::Transport(transport);

                    Ok(self)
                }
                _ => return Err(Error::NotHandshakeReply),
            },
            _ => return Err(Error::NotHandshakeState),
        }
        */
    }

    /// Send a request message.
    async fn send(&mut self, message: RequestMessage) -> Result<()> {
        let buffer = encode(&message).await?;
        self.send_binary(buffer).await
    }

    /// Send a request message and expect a response.
    async fn request(
        &mut self,
        message: RequestMessage,
    ) -> Result<ResponseMessage> {
        let buffer = encode(&message).await?;
        self.send_binary(buffer).await?;
        let response =
            self.reader.recv().await.ok_or_else(|| Error::NoReply)?;
        match response {
            ResponseMessage::Error(code, message) => {
                Err(Error::ServerError(code, message))
            }
            _ => Ok(response),
        }
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

async fn read_incoming_message(
    mut incoming: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    handler: mpsc::Sender<ResponseMessage>,
    public_key_id: String,
    peers: Peers,
) -> Result<()> {
    println!("starting client read loop {}", public_key_id);
    incoming.for_each(|reply| async {
        println!("client received message!!");
        //println!("{} received message in client", public_key_id);
        match reply {
            Ok(message) => match message {
                Message::Binary(buffer) => {
                    match decode::<ResponseMessage>(buffer).await {
                        Ok(response) => {
                            match response {
                                ResponseMessage::RelayPeer {
                                    public_key,
                                    message,
                                } => {
                                    println!("client got relay peer input...");
                                }
                                /*
                                ResponseMessage::HandshakeResponder(HandshakeType::Peer, len, buf) => {
                                    println!("got peer handshake responder message to process");                                    
                                }
                                */
                                _ => {
                                    handler.send(response).await.unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "client decode message error {}",
                                e
                            );
                        }
                    }
                }
                _ => {
                    eprintln!("client non binary response message");
                }
            },
            Err(e) => eprintln!("{}", e),
        }
    }).await;

    //while let Some(reply) = incoming.next().await {
    //}

    Ok(())
}
