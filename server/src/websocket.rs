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

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

//use axum_macros::debug_handler;

use crate::{
    server::{Service, State},
    Result,
};
use mpc_relay_protocol::{
    hex, snow::Builder, uuid::Uuid, ProtocolState, PATTERN,
};

pub type Connection = Arc<RwLock<WebSocketConnection>>;

#[derive(Debug, Deserialize)]
pub struct WebSocketQuery {
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
}

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Unique identifier for the socket connection.
    pub(crate) id: Uuid,
    /// User supplied public key.
    pub(crate) public_key: Vec<u8>,
    /// Outoing channel for messages sent to clients.
    pub(crate) outgoing: mpsc::Sender<Vec<u8>>,
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

impl WebSocketConnection {
    /// Send a buffer to the client at this socket.
    pub async fn send(&mut self, buffer: Vec<u8>) -> Result<()> {
        self.outgoing.send(buffer).await?;
        Ok(())
    }
}

/// Upgrade to a websocket connection.
//#[debug_handler]
pub async fn upgrade(
    Extension(state): Extension<State>,
    Extension(service): Extension<Service>,
    Query(query): Query<WebSocketQuery>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("websocket upgrade request");

    let mut writer = state.write().await;

    // Check access lists
    if (writer.config.allow.is_some() || writer.config.deny.is_some())
        && !writer.config.is_allowed_access(&query.public_key)
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let id = Uuid::new_v4();
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(32);
    let (incoming, service_reader) = mpsc::channel::<Vec<u8>>(32);

    let builder = Builder::new(
        PATTERN
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    let responder = builder
        .local_private_key(&writer.keypair.private)
        .remote_public_key(&query.public_key)
        .build_responder()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let protocol_state =
        ProtocolState::Handshake(Box::new(responder));

    let conn = Arc::new(RwLock::new(WebSocketConnection {
        id,
        public_key: query.public_key,
        outgoing: outgoing_tx,
        //outgoing_rx,
        incoming,
        state: Some(protocol_state),
    }));
    let socket_conn = Arc::clone(&conn);
    writer.pending.insert(id, conn);
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
        handle_socket(socket, socket_state, socket_conn, outgoing_rx)
    }))
}

async fn disconnect(state: State, conn: Connection) {
    let (id, public_key) = {
        let reader = conn.read().await;
        (reader.id, reader.public_key.clone())
    };
    tracing::trace!(public_key = ?hex::encode(&public_key), "disconnect");
    let mut writer = state.write().await;
    writer.pending.remove(&id);
    writer.active.remove(&public_key);
}

async fn handle_socket(
    socket: WebSocket,
    state: State,
    conn: Connection,
    outgoing: mpsc::Receiver<Vec<u8>>,
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
    conn: Connection,
) -> Result<()> {
    let tx = {
        let reader = conn.read().await;
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
    mut outgoing: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(buffer) = outgoing.recv().await {
        if sender.send(Message::Binary(buffer)).await.is_err() {
            disconnect(state, Arc::clone(&conn)).await;
            return Ok(());
        }
    }
    Ok(())
}
