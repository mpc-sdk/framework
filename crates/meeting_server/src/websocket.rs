use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Query,
    },
    http::StatusCode,
    response::Response,
};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use serde::Deserialize;

use std::{fmt, sync::Arc};
use tokio::sync::{mpsc, RwLock};

//use axum_macros::debug_handler;

use crate::{
    server::{Service, State},
    Result,
};
use polysig_protocol::{hex, uuid::Uuid, zlib};

pub type Connection = Arc<RwLock<WebSocketConnection>>;

/// Query string for initiating websocket connections.
#[derive(Debug, Deserialize)]
pub struct WebSocketQuery {
    /// Public key offered by the client socket.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
}

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Unique identifier for the socket connection.
    pub(crate) id: Uuid,
    /// Outoing channel for messages sent to clients.
    pub(crate) outgoing: mpsc::Sender<Message>,
    // Incoming channel for messages received from clients.
    pub(crate) incoming: mpsc::Sender<Vec<u8>>,
}

impl fmt::Debug for WebSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketConnection")
            .field("id", &self.id)
            .finish()
    }
}

impl WebSocketConnection {
    /// Send a buffer to the client at this socket.
    pub async fn send(&mut self, buffer: Vec<u8>) -> Result<()> {
        /*
        let deflated = zlib::deflate(&buffer)?;
        self.outgoing.send(Message::Binary(deflated)).await?;
        */
        Ok(())
    }
}

/// Upgrade to a websocket connection.
//#[debug_handler]
pub async fn upgrade(
    Extension(state): Extension<State>,
    Extension(service): Extension<Service>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("websocket upgrade request");

    let mut writer = state.write().await;

    let id = Uuid::new_v4();
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<Message>(32);
    let (incoming, service_reader) = mpsc::channel::<Vec<u8>>(32);

    let conn = Arc::new(RwLock::new(WebSocketConnection {
        id,
        outgoing: outgoing_tx.clone(),
        incoming,
    }));
    let socket_conn = Arc::clone(&conn);
    drop(writer);

    let socket_state = Arc::clone(&state);
    Ok(ws.on_upgrade(move |socket| {
        service
            .listen_socket(Arc::clone(&socket_conn), service_reader);
        handle_socket(
            socket,
            socket_state,
            socket_conn,
            outgoing_rx,
            outgoing_tx,
        )
    }))
}

async fn disconnect(state: State, conn: Connection) {
    /*
    let (id, public_key) = {
        let reader = conn.read().await;
        (reader.id, reader.public_key.clone())
    };
    */
    tracing::debug!("disconnect");
    /*
    let mut writer = state.write().await;
    writer.pending.remove(&id);
    writer.active.remove(&public_key);
    */
}

async fn handle_socket(
    socket: WebSocket,
    state: State,
    conn: Connection,
    outgoing_rx: mpsc::Receiver<Message>,
    outgoing_tx: mpsc::Sender<Message>,
) {
    let (writer, reader) = socket.split();

    tokio::spawn(write(
        writer,
        Arc::clone(&state),
        Arc::clone(&conn),
        outgoing_rx,
    ));
    tokio::spawn(read(
        reader,
        Arc::clone(&state),
        Arc::clone(&conn),
        outgoing_tx,
    ));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    state: State,
    conn: Connection,
    outgoing_tx: mpsc::Sender<Message>,
) -> Result<()> {
    /*
    let tx = {
        let reader = conn.read().await;
        reader.incoming.clone()
    };
    */

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(buffer) => {
                    /*
                    if let Ok(inflated) = zlib::inflate(&buffer) {
                        tx.send(inflated).await?;
                    } else {
                        tracing::warn!(
                            "could not inflate message buffer"
                        );
                    }
                    */
                }
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(frame) => {
                    let _ =
                        outgoing_tx.send(Message::Close(frame)).await;
                    return Ok(());
                }
            },
            Err(e) => {
                tracing::warn!(error = %e,"ws_server::read_error");
                disconnect(state, Arc::clone(&conn)).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write(
    mut sender: SplitSink<WebSocket, Message>,
    state: State,
    conn: Connection,
    mut outgoing_rx: mpsc::Receiver<Message>,
) -> Result<()> {
    while let Some(message) = outgoing_rx.recv().await {
        if let Err(error) = sender.send(message).await {
            tracing::warn!(error = %error, "ws_server::write_error");
            disconnect(state, Arc::clone(&conn)).await;
            return Ok(());
        }
    }
    Ok(())
}
