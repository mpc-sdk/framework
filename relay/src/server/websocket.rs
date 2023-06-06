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
use snow::Builder;

use std::sync::Arc;
use tokio::sync::{
    broadcast::{self, Receiver, Sender},
    mpsc, RwLock,
};

use uuid::Uuid;
//use axum_macros::debug_handler;

use super::{Service, State};
use crate::{constants::PATTERN, ProtocolState, Result};

pub type Connection = Arc<RwLock<WebSocketConnection>>;

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Unique identifier for the socket connection.
    pub(crate) id: Uuid,
    /// Outoing channel for messages sent to clients.
    pub(crate) outgoing: Sender<Vec<u8>>,
    // Incoming channel for messages received from clients.
    pub(crate) incoming: mpsc::Sender<Vec<u8>>,
    /// Protocol state for this connection.
    ///
    /// Use an option here as we need to call 
    /// into_transport_mode() which requires self 
    /// so we move out of the option and convert to 
    /// transport mode and then put it back.
    pub(crate) state: Option<ProtocolState>,
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
    let (outgoing, _) = broadcast::channel::<Vec<u8>>(32);
    let (incoming, service_reader) = mpsc::channel::<Vec<u8>>(32);

    let mut builder = Builder::new(
        PATTERN
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    let responder = builder
        .local_private_key(&writer.keypair.private)
        //.remote_public_key(&keypair1.public)
        .build_responder()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let protocol_state = ProtocolState::Handshake(responder);

    let conn = Arc::new(RwLock::new(WebSocketConnection {
        id: id.clone(),
        outgoing,
        incoming,
        state: Some(protocol_state),
    }));
    let socket_conn = Arc::clone(&conn);
    writer.sockets.insert(id, conn);
    drop(writer);

    let service_writer = {
        let reader = socket_conn.read().await;
        reader.outgoing.clone()
    };

    let socket_state = Arc::clone(&state);
    Ok(ws.on_upgrade(move |socket| {
        service.listen_socket(
            Arc::clone(&socket_conn),
            service_reader,
            service_writer,
        );
        handle_socket(socket, socket_state, socket_conn)
    }))
}

async fn disconnect(state: State, conn: Connection) {
    let id = {
        let reader = conn.read().await;
        reader.id.clone()
    };
    let mut writer = state.write().await;
    writer.sockets.remove(&id);
}

async fn handle_socket(socket: WebSocket, state: State, conn: Connection) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(writer, Arc::clone(&state), Arc::clone(&conn)));
    tokio::spawn(read(reader, Arc::clone(&state), Arc::clone(&conn)));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    state: State,
    conn: Connection,
) -> Result<()> {
    let mut tx = {
        let mut reader = conn.read().await;
        reader.incoming.clone()
    };

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(buffer) => {
                    tx.send(buffer).await?;
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
    conn: Connection,
) -> Result<()> {
    let mut outgoing = {
        let reader = conn.read().await;
        reader.outgoing.subscribe()
    };
    while let Ok(buffer) = outgoing.recv().await {
        if sender.send(Message::Binary(buffer)).await.is_err() {
            disconnect(state, Arc::clone(&conn)).await;
            return Ok(());
        }
    }
    Ok(())
}
