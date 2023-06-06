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

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Broadcast sender for websocket message.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected sockets for the client.
    pub(crate) tx: Sender<Vec<u8>>,
}

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<State>,
    //Query(query): Query<QueryMessage>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("websocket upgrade request");

    let mut writer = state.write().await;

    /*
    let conn = if let Some(conn) = writer.sockets.get_mut(&token.address) {
        conn
    } else {
        let (tx, _) = broadcast::channel::<Vec<u8>>(32);
        writer
            .sockets
            .entry(token.address)
            .or_insert(WebSocketConnection { tx, clients: 0 })
    };

    let rx = conn.tx.subscribe();
    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, state, rx)
    }))
    */

    todo!();
}

async fn disconnect(
    state: State,
    //address: Address,
    //session_id: Uuid,
) {

    /*
    let mut writer = state.write().await;

    // Sessions for websocket connections have the keep alive
    // flag so we must remove them on disconnect
    writer.sessions.remove_session(&session_id);

    let clients = if let Some(conn) = writer.sockets.get_mut(&address) {
        conn.clients -= 1;
        Some(conn.clients)
    } else {
        None
    };

    if let Some(clients) = clients {
        if clients == 0 {
            writer.sockets.remove(&address);
        }
    }
    */
}

async fn handle_socket(
    socket: WebSocket,
    state: State,
    outgoing: Receiver<Vec<u8>>,
) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(writer, Arc::clone(&state), outgoing));
    tokio::spawn(read(reader, Arc::clone(&state)));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    state: State,
) -> Result<()> {
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(_) => {}
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => {
                    disconnect(state /*, address, session_id */).await;
                    return Ok(());
                }
            },
            Err(e) => {
                disconnect(state /*, address, session_id */).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write(
    mut sender: SplitSink<WebSocket, Message>,
    state: State,
    mut outgoing: Receiver<Vec<u8>>,
) -> Result<()> {
    while let Ok(msg) = outgoing.recv().await {
        /*
        let mut writer = state.write().await;
        let session = writer
            .sessions
            .get_mut(&session_id)
            .expect("failed to locate websocket session");

        let aead = match session.encrypt(&msg).await {
            Ok(aead) => aead,
            Err(e) => {
                drop(writer);
                disconnect(state, address, session_id).await;
                return Err(e.into());
            }
        };

        drop(writer);

        match encode(&aead).await {
            Ok(buffer) => {
                if sender.send(Message::Binary(buffer)).await.is_err() {
                    disconnect(state, address, session_id).await;
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::error!("{}", e);
                disconnect(state, address, session_id).await;
                return Err(e.into());
            }
        }
        */
    }
    Ok(())
}
