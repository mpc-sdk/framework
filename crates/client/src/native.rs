use async_stream::stream;
use futures::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
    StreamExt,
};
use serde::Serialize;
use std::{collections::HashSet, sync::Arc};
use tokio::{
    net::TcpStream,
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream,
    WebSocketStream,
};

use polysig_protocol::{
    channel::encrypt_server_channel, decode, encode, hex,
    http::StatusCode, snow::Builder, zlib, Encoding, Event,
    HandshakeMessage, JsonMessage, MeetingResponse, PublicKeys,
    MeetingId, MeetingRequest, OpaqueMessage, ProtocolState,
    RequestMessage, ResponseMessage, ServerMessage, SessionId,
    SessionRequest, TransparentMessage, UserId,
};

use super::{
    encrypt_peer_channel,
    event_loop::{
        event_loop_run_impl, EventLoop, EventStream, IncomingMessage,
        InternalMessage,
    },
    Peers, Server,
};
use crate::{
    client_impl, client_transport_impl, ClientOptions, Error, Result,
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

        let server = if let (Some(keypair), Some(server_public_key)) =
            (&options.keypair, &options.server_public_key)
        {
            let builder = Builder::new(options.params()?);
            let handshake = builder
                .local_private_key(keypair.private_key())
                .remote_public_key(server_public_key)
                .build_initiator()?;

            // State for the server transport
            Arc::new(RwLock::new(Some(ProtocolState::Handshake(
                Box::new(handshake),
            ))))
        } else {
            Arc::new(RwLock::new(None))
        };

        // Channel for writing outbound messages to send
        // to the server
        let (outbound_tx, outbound_rx) =
            mpsc::unbounded_channel::<InternalMessage>();

        let peers = Arc::new(RwLock::new(Default::default()));
        let options = Arc::new(options);
        let client = Self {
            options: options.clone(),
            outbound_tx: outbound_tx.clone(),
            server: server.clone(),
            peers: peers.clone(),
        };

        // Decoded socket messages are sent over this channel
        let (inbound_tx, inbound_rx) =
            mpsc::unbounded_channel::<IncomingMessage>();

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
        options: Arc<ClientOptions>,
        incoming: Message,
        event_proxy: &mut mpsc::UnboundedSender<IncomingMessage>,
    ) -> Result<()> {
        if let Message::Binary(buffer) = incoming {
            let inflated = zlib::inflate(&buffer)?;

            if options.is_encrypted() {
                let response: ResponseMessage =
                    decode(inflated).await?;
                event_proxy
                    .send(IncomingMessage::Response(response))?;
            } else {
                let response: MeetingResponse =
                    serde_json::from_slice(&inflated)?;
                event_proxy
                    .send(IncomingMessage::Meeting(response))?;
            }
        }
        Ok(())
    }

    /// Send a message to the socket and flush the stream.
    pub(crate) async fn send_message(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let encoded = encode(&message).await?;
        self.send_buffer(&encoded).await
    }

    /// Send a message to the socket and flush the stream.
    pub(crate) async fn send_buffer(
        &mut self,
        buffer: &[u8],
    ) -> Result<()> {
        let deflated = zlib::deflate(buffer)?;

        tracing::debug!(
            encoded_length = buffer.len(),
            deflated_length = deflated.len(),
            "send_buffer"
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
