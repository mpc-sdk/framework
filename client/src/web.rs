use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{ErrorEvent, MessageEvent, WebSocket};

use async_stream::stream;
use futures::pin_mut;
use fastsink::Action;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use mpc_relay_protocol::{
    snow::Builder, ProtocolState, RequestMessage, ResponseMessage,
    PATTERN, encode, decode,
};

use super::{ClientOptions, Peers, Server};
use crate::{event_loop::EventLoop, Result};

type WsMessage = Vec<u8>;
type WsError = crate::Error;
type WsReadStream = WebSocket;
type WsWriteStream = WebSocket;

/// Client for the web platform.
pub struct WebClient {
    options: Arc<ClientOptions>,
    ws: WebSocket,
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

        let cloned_ws = ws.clone();
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
            ws: ws.clone(),
            server: Arc::clone(&server),
            peers: Arc::clone(&peers),
        };

        // Decoded socket messages are sent over this channel
        let (msg_tx, msg_rx) = mpsc::channel::<ResponseMessage>(32);
        
        // Proxy stream from the websocket message event closure
        // to the event loop
        let ws_reader = stream! {
            while let Some(message) = ws_msg_rx.recv().await {
                yield message;
            }
        };

        let ws_writer = fastsink::make_sink(
            ws.clone(),
            |mut ws, action: Action<Vec<u8>>| async move {
                match action {
                    Action::Send(x) => {
                        ws.send_with_u8_array(&x)?;
                    },
                    Action::Flush => todo!(),
                    Action::Close => ws.close()?,
                }
                Ok::<_, crate::Error>(ws)
            },
        );

        pin_mut!(ws_reader);
        pin_mut!(ws_writer);

        let event_loop = EventLoop {
            options,
            ws_reader,
            ws_writer,
            message_tx: msg_tx,
            message_rx: msg_rx,
            outbound_tx,
            outbound_rx,
            server,
            peers,
            builder: Box::new(|message| {
                Box::pin(async move {
                    todo!();
                    //Ok(encode(&message).await?)
                })
            }),
        };

        Ok(client)
    }
}
