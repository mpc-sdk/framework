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
    encrypt_peer_channel,
    event_loop::{event_loop_run_impl, EventLoop},
    Peers, Server,
};
use crate::{client_impl, ClientOptions, Error, Event, Result};

type WsMessage = Message;
type WsError = tokio_tungstenite::tungstenite::Error;
type WsReadStream =
    SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
type WsWriteStream =
    SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

/// Event loop for the websocket client.
pub type NativeEventLoop =
    EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream>;

/// Relay service websocket client.
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
        };

        Ok((client, event_loop))
    }

    client_impl!();
}

impl EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream> {
    /// Receive and decode socket messages then send to
    /// the messages channel.
    pub(crate) async fn read_message(
        incoming: Message,
        event_proxy: &mut mpsc::Sender<ResponseMessage>,
    ) -> Result<()> {
        if let Message::Binary(buffer) = incoming {
            let response: ResponseMessage = decode(buffer).await?;
            event_proxy.send(response).await?;
        }
        Ok(())
    }

    /// Send a message to the socket and flush the stream.
    pub(crate) async fn send_message(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let message = Message::Binary(encode(&message).await?);

        self.ws_writer
            .send(message)
            .await
            .map_err(|_| Error::WebSocketSend)?;
        Ok(self
            .ws_writer
            .flush()
            .await
            .map_err(|_| Error::WebSocketSend)?)
    }

    event_loop_run_impl!();
}
