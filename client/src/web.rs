use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{ErrorEvent, MessageEvent, WebSocket};

use async_stream::stream;
use fastsink::Action;
use futures::{
    select, stream::BoxStream, FutureExt, SinkExt, StreamExt,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use mpc_relay_protocol::{
    channel::encrypt_server_channel, decode, encode, hex,
    snow::Builder, Encoding, HandshakeMessage, OpaqueMessage,
    ProtocolState, RequestMessage, ResponseMessage, ServerMessage,
    SessionId, SessionRequest, TransparentMessage, PATTERN,
};

use crate::{
    client_impl, encrypt_peer_channel,
    event_loop::{event_loop_run_impl, EventLoop},
    ClientOptions, Error, Event, Peers, Result, Server,
};

type WsMessage = Vec<u8>;
type WsError = Error;
type WsReadStream = BoxStream<'static, Result<Vec<u8>>>;
type WsWriteStream =
    Box<dyn futures::Sink<Vec<u8>, Error = Error> + Send + Unpin>;

/// Event loop for the web client.
pub type WebEventLoop =
    EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream>;

/// Client for the web platform.
pub struct WebClient {
    options: Arc<ClientOptions>,
    outbound_tx: mpsc::Sender<RequestMessage>,
    server: Server,
    peers: Peers,
}

//#[wasm_bindgen]
impl WebClient {
    /// Create a new web client.
    pub async fn new(
        server: &str,
        options: ClientOptions,
    ) -> Result<WebClient> {
        let ws = WebSocket::new(server)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let (ws_msg_tx, mut ws_msg_rx) = mpsc::channel(32);
        let msg_tx = Box::new(ws_msg_tx);
        let msg_tx_ref: &'static mpsc::Sender<Result<Vec<u8>>> =
            Box::leak(msg_tx);

        let onmessage_callback = Closure::<dyn FnMut(_)>::new(
            move |e: MessageEvent| {
                spawn_local(async move {
                    if let Ok(abuf) =
                        e.data().dyn_into::<js_sys::ArrayBuffer>()
                    {
                        log::info!(
                        "message event, received array buffer: {:?}", abuf);
                        let array = js_sys::Uint8Array::new(&abuf);
                        let len = array.byte_length() as usize;
                        let buffer = array.to_vec();
                        msg_tx_ref.send(Ok(buffer)).await.unwrap();
                    } else {
                        log::warn!(
                            "unknown message event: {:?}",
                            e.data()
                        );
                    }
                });
            },
        );
        ws.set_onmessage(Some(
            onmessage_callback.as_ref().unchecked_ref(),
        ));
        onmessage_callback.forget();

        let onerror_callback =
            Closure::<dyn FnMut(_)>::new(move |e: ErrorEvent| {
                log::error!("error event: {:?}", e);
            });
        ws.set_onerror(Some(
            onerror_callback.as_ref().unchecked_ref(),
        ));
        onerror_callback.forget();

        let (open_tx, mut open_rx) = mpsc::channel(1);

        let onopen_callback = Closure::once(move || {
            log::info!("websocket open event");
            spawn_local(async move {
                open_tx.send(()).await.unwrap();
            });
            /*
            log::info!("socket opened");
            // send off binary message
            match cloned_ws.send_with_u8_array(&[0, 1, 2, 3]) {
                Ok(_) => {
                    log::info!("binary message successfully sent")
                }
                Err(err) => {
                    log::info!("error sending message: {:?}", err)
                }
            }
            */
        });
        ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));

        let _ = open_rx.recv().await;
        drop(open_rx);

        log::info!("socket opened, returning the client");

        // Channel for writing outbound messages to send
        // to the server
        let (outbound_tx, outbound_rx) =
            mpsc::channel::<RequestMessage>(32);

        let builder = Builder::new(PATTERN.parse()?);
        let handshake = builder
            .local_private_key(&options.keypair.private)
            .remote_public_key(&options.server_public_key)
            .build_initiator()?;

        // State for the server transport
        let server = Arc::new(RwLock::new(Some(
            ProtocolState::Handshake(Box::new(handshake)),
        )));

        let peers = Arc::new(RwLock::new(Default::default()));
        let options = Arc::new(options);

        let client = WebClient {
            options: Arc::clone(&options),
            outbound_tx: outbound_tx.clone(),
            server: Arc::clone(&server),
            peers: Arc::clone(&peers),
        };

        // Decoded socket messages are sent over this channel
        let (message_tx, message_rx) =
            mpsc::channel::<ResponseMessage>(32);

        // Proxy stream from the websocket message event closure
        // to the event loop
        let ws_reader = Box::pin(stream! {
            while let Some(message) = ws_msg_rx.recv().await {
                yield message;
            }
        });

        let ws_writer = Box::pin(fastsink::make_sink(
            ws.clone(),
            |ws, action: Action<Vec<u8>>| async move {
                match action {
                    Action::Send(x) => {
                        ws.send_with_u8_array(&x)?;
                    }
                    Action::Flush => todo!(),
                    Action::Close => ws.close()?,
                }
                Ok::<_, crate::Error>(ws)
            },
        ));

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

        Ok(client)
    }

    client_impl!();
}

impl EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream> {
    /// Receive and decode socket messages then send to
    /// the messages channel.
    pub(crate) async fn read_message(
        incoming: WsMessage,
        event_proxy: &mut mpsc::Sender<ResponseMessage>,
    ) -> Result<()> {
        let response: ResponseMessage = decode(&incoming).await?;
        event_proxy.send(response).await?;
        Ok(())
    }

    /// Send a message to the socket and flush the stream.
    pub(crate) async fn send_message(
        &mut self,
        message: RequestMessage,
    ) -> Result<()> {
        let message = encode(&message).await?;
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
