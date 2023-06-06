use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use snow::Keypair;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest, handshake::client::Response,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use snow::{Builder, HandshakeState, TransportState};

use crate::{constants::PATTERN, Error, ProtocolState, Result};

/// Native websocket client using the tokio tungstenite library.
pub struct NativeClient {
    keypair: Keypair,
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    response: Response,
    state: ProtocolState,
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

        let mut builder = Builder::new(PATTERN.parse()?);
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
        })
    }

    /// Perform initial handshake with the server.
    pub async fn handshake(mut self) -> Result<Self> {
        let (len, request) = match &mut self.state {
            ProtocolState::Handshake(initiator) => {
                let mut request = vec![0u8; 1024];
                let len = initiator.write_message(&[], &mut request)?;
                (len, request)
            }
            _ => return Err(Error::NotHandshakeState),
        };

        let reply = self.send_recv_binary(request).await?;
        match self.state {
            ProtocolState::Handshake(mut initiator) => {
                let mut read_buf = vec![0u8; 1024];
                initiator.read_message(&reply[..len], &mut read_buf)?;

                let transport = initiator.into_transport_mode()?;
                self.state = ProtocolState::Transport(transport);

                Ok(self)
            }
            _ => return Err(Error::NotHandshakeState),
        }
    }

    /// Send a binary message to the server.
    pub async fn send_binary(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.send(Message::Binary(buffer)).await
    }

    /// Send a binary message to the server and wait for a reply.
    pub async fn send_recv_binary(
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

    /// Send a message to the server and flush the stream.
    pub async fn send(&mut self, message: Message) -> Result<()> {
        self.write.send(message).await?;
        Ok(self.write.flush().await?)
    }
}
