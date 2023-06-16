use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{ErrorEvent, MessageEvent, WebSocket};

use async_stream::stream;
use futures::{
    select, stream::BoxStream, FutureExt, Sink, SinkExt, StreamExt,
};
use serde::Serialize;
use std::{pin::Pin, sync::Arc};
use tokio::sync::{mpsc, RwLock};

use mpc_relay_protocol::{
    channel::encrypt_server_channel, decode, encode, hex,
    snow::Builder, Encoding, HandshakeMessage, OpaqueMessage,
    ProtocolState, RequestMessage, ResponseMessage, ServerMessage,
    SessionId, SessionRequest, TransparentMessage, PATTERN,
};

use crate::{
    client_impl, client_transport_impl, encrypt_peer_channel,
    event_loop::{event_loop_run_impl, EventLoop},
    ClientOptions, Error, Event, Peers, Result, Server,
};

type WsMessage = Vec<u8>;
type WsError = Error;
type WsReadStream = BoxStream<'static, Result<Vec<u8>>>;
type WsWriteStream = Pin<
    Box<dyn futures::Sink<Vec<u8>, Error = Error> + Send + Unpin>,
>;

/// Event loop for the web client.
pub type WebEventLoop =
    EventLoop<WsMessage, WsError, WsReadStream, WsWriteStream>;

/// Client for the web platform.
#[derive(Clone)]
pub struct WebClient {
    options: Arc<ClientOptions>,
    outbound_tx: mpsc::Sender<RequestMessage>,
    server: Server,
    peers: Peers,
    ptr: *mut mpsc::Sender<Result<Vec<u8>>>,
}

impl WebClient {
    /// Create a new web client.
    pub async fn new(
        server: &str,
        options: ClientOptions,
    ) -> Result<(WebClient, WebEventLoop)> {
        let ws = WebSocket::new(server)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let (ws_msg_tx, mut ws_msg_rx) = mpsc::channel(32);
        let msg_tx = Box::new(ws_msg_tx);

        let ptr = Box::into_raw(msg_tx);
        unsafe {
            let msg_proxy = &*(ptr as *const _)
                as &'static mpsc::Sender<Result<Vec<u8>>>;
            let onmessage_callback = Closure::<dyn FnMut(_)>::new(
                move |e: MessageEvent| {
                    spawn_local(async move {
                        if let Ok(buf) =
                            e.data().dyn_into::<js_sys::ArrayBuffer>()
                        {
                            let array = js_sys::Uint8Array::new(&buf);
                            let buffer = array.to_vec();
                            msg_proxy.send(Ok(buffer)).await.unwrap();
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
        }

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
            spawn_local(async move {
                open_tx.send(()).await.unwrap();
            });
        });
        ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));

        let _ = open_rx.recv().await;
        drop(open_rx);

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
            ptr,
        };

        // Proxy stream from the websocket message event closure
        // to the event loop
        let ws_reader = Box::pin(stream! {
            while let Some(message) = ws_msg_rx.recv().await {
                yield message;
            }
        });

        let ws_writer = Box::pin(WebSocketSink { ws });

        // Decoded socket messages are sent over this channel
        let (inbound_tx, inbound_rx) =
            mpsc::channel::<ResponseMessage>(32);

        let event_loop: WebEventLoop = EventLoop {
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

client_transport_impl!(WebClient);

impl Drop for WebClient {
    fn drop(&mut self) {
        unsafe {
            std::ptr::drop_in_place(self.ptr);
        }
    }
}

unsafe impl Send for WebClient {}

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

use core::task::{Context, Poll};

struct WebSocketSink {
    ws: WebSocket,
}

impl Sink<Vec<u8>> for WebSocketSink {
    type Error = Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<()> {
        unsafe { self.get_unchecked_mut() }
            .ws
            .send_with_u8_array(&item)?;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// The `WebSocket` type stores a `JsValue`
// which contains a raw pointer which is not `Send`
// but we need `Send` for the event loop when running
// in native code (multi-threaded context).
//
// We know that the webassembly client should only
// ever run in a single threaded context so we can
// implement `Send` to appease the compiler.
unsafe impl Send for WebSocketSink {}
