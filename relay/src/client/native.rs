use crate::Result;
use tokio::net::TcpStream;
use futures::{StreamExt, stream::{SplitSink, SplitStream}, sink::SinkExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        protocol::Message,
        client::IntoClientRequest, handshake::client::Response,
    },
    MaybeTlsStream, WebSocketStream,
};

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
        Ok(Self{
            write,
            read,
            response,
        })
    }
    
    /// Send a binary message to the server.
    pub async fn send_binary(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.send(Message::Binary(buffer)).await
    }
    
    /// Send a message to the server and flush the stream.
    pub async fn send(&mut self, message: Message) -> Result<()> {
        self.write.send(message).await?;
        Ok(self.write.flush().await?)
    }
}
