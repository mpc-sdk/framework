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

use std::sync::Arc;
use tokio::sync::{
    broadcast::{self, Receiver, Sender},
    RwLock,
};

use super::State;
use crate::Result;
use uuid::Uuid;

use axum_macros::debug_handler;

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Unique identifier for the socket connection.
    pub(crate) id: Uuid,

    /// Outoing channel for messages sent to clients.
    pub(crate) outgoing: Sender<Vec<u8>>,
    // Incoming channel for messages received from clients.
    //pub(crate) incoming: Receiver<Vec<u8>>,
}

/// Upgrade to a websocket connection.
#[debug_handler]
pub async fn upgrade(
    Extension(state): Extension<State>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("websocket upgrade request");

    let mut writer = state.write().await;
    let id = Uuid::new_v4();
    let (outgoing, _) = broadcast::channel::<Vec<u8>>(32);
    //let (_, incoming) = broadcast::channel::<Vec<u8>>(32);
    let conn = Arc::new(WebSocketConnection {
        id: id.clone(),
        outgoing,
        //incoming,
    });

    let socket_conn = Arc::clone(&conn);
    writer.sockets.insert(id, conn);
    drop(writer);

    let rx = socket_conn.outgoing.subscribe();
    let socket_state = Arc::clone(&state);
    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, socket_state, socket_conn, rx)
    }))
}

async fn disconnect(
    state: State,
    conn: Arc<WebSocketConnection>,
) {
    let mut writer = state.write().await;
    writer.sockets.remove(&conn.id);
}

async fn handle_socket(
    socket: WebSocket,
    state: State,
    conn: Arc<WebSocketConnection>,
    outgoing: Receiver<Vec<u8>>,
) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(
        writer,
        Arc::clone(&state),
        Arc::clone(&conn),
        outgoing,
    ));
    tokio::spawn(read(reader, Arc::clone(&state), Arc::clone(&conn)));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    state: State,
    conn: Arc<WebSocketConnection>,
) -> Result<()> {
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(_) => {
                    println!("read binary message...");
                }
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => {
                    disconnect(state, Arc::clone(&conn)).await;
                    return Ok(());
                }
            },
            Err(e) => {
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
    conn: Arc<WebSocketConnection>,
    mut outgoing: Receiver<Vec<u8>>,
) -> Result<()> {
    while let Ok(buffer) = outgoing.recv().await {
        if sender.send(Message::Binary(buffer)).await.is_err() {
            disconnect(state, Arc::clone(&conn)).await;
            return Ok(());
        }
    }
    Ok(())
}
