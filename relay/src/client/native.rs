use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use snow::{Builder, Keypair};
use std::collections::HashMap;
use tokio::net::TcpStream;
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
    RequestMessage, ResponseMessage, Result,
};

/// Native websocket client using the tokio tungstenite library.
pub struct NativeClient {
    keypair: Keypair,
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    response: Response,
    state: ProtocolState,
    peers: HashMap<Vec<u8>, ProtocolState>,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new<R>(
        request: R,
        keypair: Keypair,
        public_key: Vec<u8>,
    ) -> Result<Self>
    where
        R: IntoClientRequest + Unpin,
    {
        let (stream, response) = connect_async(request).await?;
        let (write, read) = stream.split();

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&keypair.private)
            .remote_public_key(&public_key)
            .build_initiator()?;

        Ok(Self {
            keypair,
            write,
            read,
            response,
            state: ProtocolState::Handshake(handshake),
            peers: Default::default(),
        })
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
    }

    /// Initiate handshake with a peer.
    pub async fn peer_handshake(
        &mut self,
        public_key: impl AsRef<[u8]>,
    ) -> Result<()> {
        if self.peers.get(public_key.as_ref()).is_some() {
            return Err(Error::PeerAlreadyExists);
        }

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&self.keypair.private)
            .remote_public_key(public_key.as_ref())
            .build_initiator()?;
        let peer_state = ProtocolState::Handshake(handshake);

        let state = self
            .peers
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

        let inner_request = RequestMessage::HandshakeInitiator(len, payload);
        let inner_message = encode(&inner_request).await?;

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
    async fn send(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let buffer = encode(&message).await?;
        self.send_binary(buffer).await
    }

    /// Send a request message and expect a response.
    async fn request(
        &mut self,
        message: RequestMessage,
    ) -> Result<ResponseMessage> {
        let buffer = encode(&message).await?;
        let reply = self.send_recv_binary(buffer).await?;
        let response: ResponseMessage = decode(&reply).await?;
        match response {
            ResponseMessage::Error(code, message) => {
                Err(Error::ServerError(code, message))
            }
            _ => Ok(response),
        }
    }

    /// Send a binary message to the server and wait for a reply.
    async fn send_recv_binary(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.send_binary(buffer).await?;
        while let Some(reply) = self.read.next().await {
            let message = reply?;
            return match message {
                Message::Binary(buffer) => Ok(buffer),
                _ => break,
            };
        }
        Err(Error::BinaryReplyExpected)
    }

    /// Send a binary message to the server.
    async fn send_binary(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.send_socket(Message::Binary(buffer)).await
    }

    /// Send a message to the socket and flush the stream.
    async fn send_socket(&mut self, message: Message) -> Result<()> {
        self.write.send(message).await?;
        Ok(self.write.flush().await?)
    }
}
