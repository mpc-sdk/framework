use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest, handshake::client::Response,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use crate::{Error, Result};

/// Native websocket client using the tokio tungstenite library.
pub struct NativeClient {
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    response: Response,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new<R>(request: R) -> Result<Self>
    where
        R: IntoClientRequest + Unpin,
    {
        let (stream, response) = connect_async(request).await?;
        let (write, read) = stream.split();
        Ok(Self {
            write,
            read,
            response,
        })
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
