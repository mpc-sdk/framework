use async_stream::stream;
use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashSet, sync::Arc};
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream,
    WebSocketStream,
};

use mpc_protocol::{
    channel::encrypt_server_channel, decode, encode, hex,
    http::StatusCode, snow::Builder, zlib, Encoding,
    HandshakeMessage, MeetingId, OpaqueMessage, ProtocolState,
    RequestMessage, ResponseMessage, ServerMessage, SessionId,
    SessionRequest, TransparentMessage, UserId,
};

use super::{
    encrypt_peer_channel,
    event_loop::{
        event_loop_run_impl, EventLoop, EventStream, InternalMessage,
    },
    Peers, Server,
};
use crate::{
    client_impl, client_transport_impl, ClientOptions, Error, Event,
    Result,
};

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
    outbound_tx: mpsc::UnboundedSender<InternalMessage>,
    server: Server,
    peers: Peers,
}

impl NativeClient {
    /// Create a new native client.
    pub async fn new(
        server: &str,
        options: ClientOptions,
    ) -> Result<(Self, NativeEventLoop)> {
        let (stream, response) = connect_async(server).await?;

        let status: u16 = response.status().into();
        if status != StatusCode::SWITCHING_PROTOCOLS.as_u16() {
            return Err(Error::ConnectError(
                StatusCode::from_u16(status).unwrap(),
                response.status().to_string(),
            ));
        }

        let (ws_writer, ws_reader) = stream.split();

        let builder = Builder::new(options.params()?);
        let handshake = builder
            .local_private_key(options.keypair.private_key())
            .remote_public_key(&options.server_public_key)
            .build_initiator()?;

        // Channel for writing outbound messages to send
        // to the server
        let (outbound_tx, outbound_rx) =
            mpsc::unbounded_channel::<InternalMessage>();

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
        let (inbound_tx, inbound_rx) =
            mpsc::unbounded_channel::<ResponseMessage>();

        let event_loop = EventLoop {
            options,
            ws_reader,
            ws_writer,
            inbound_tx,
            inbound_rx,
            outbound_tx,
            outbound_rx,
            server,
            peers,
        };

        Ok((client, event_loop))
    }

    client_impl!();
}

client_transport_impl!(NativeClient);

impl EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream> {
    /// Receive and decode socket messages then send to
    /// the messages channel.
    pub(crate) async fn read_message(
        incoming: Message,
        event_proxy: &mut mpsc::UnboundedSender<ResponseMessage>,
    ) -> Result<()> {
        if let Message::Binary(buffer) = incoming {
            let inflated = zlib::inflate(&buffer)?;
            let response: ResponseMessage = decode(inflated).await?;
            event_proxy.send(response)?;
        }
        Ok(())
    }

    /// Send a message to the socket and flush the stream.
    pub(crate) async fn send_message(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let encoded = encode(&message).await?;
        let deflated = zlib::deflate(&encoded)?;

        tracing::debug!(
            encoded_length = encoded.len(),
            deflated_length = deflated.len(),
            "send_message"
        );

        let message = Message::Binary(deflated);

        self.ws_writer
            .send(message)
            .await
            .map_err(|_| Error::WebSocketSend)?;
        self.ws_writer
            .flush()
            .await
            .map_err(|_| Error::WebSocketSend)
    }

    async fn handle_close_message(self) -> Result<()> {
        let mut websocket: WebSocketStream<
            MaybeTlsStream<TcpStream>,
        > = self
            .ws_reader
            .reunite(self.ws_writer)
            .map_err(|_| Error::StreamReunite)?;

        websocket.close(None).await?;
        Ok(())
    }

    event_loop_run_impl!();
}
