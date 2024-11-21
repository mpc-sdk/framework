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

use std::{fmt, sync::Arc};
use tokio::sync::{mpsc, RwLock};

//use axum_macros::debug_handler;

use crate::{server::State, Result};
use polysig_protocol::{uuid::Uuid, zlib, MeetingServerMessage};

pub type Connection = Arc<RwLock<WebSocketConnection>>;

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Unique identifier for the socket connection.
    pub(crate) id: Uuid,
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
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("websocket upgrade request");

    /*
     */

    let id = Uuid::new_v4();
    let conn = Arc::new(RwLock::new(WebSocketConnection { id }));
    let socket_conn = Arc::clone(&conn);

    {
        let mut writer = state.write().await;
        // TODO: keep track of connections
        // writer
    }

    let socket_state = Arc::clone(&state);
    Ok(ws.on_upgrade(move |socket| {
        /*
        tokio::spawn(listen(
            Arc::clone(&self.state),
            Arc::clone(&conn),
            reader,
        ));
        */

        handle_socket(socket, socket_state, socket_conn)
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
) {
    let (writer, reader) = socket.split();

    /*
    tokio::spawn(write(
        writer,
        Arc::clone(&state),
        Arc::clone(&conn),
    ));
    */
    tokio::spawn(read(reader, Arc::clone(&state), Arc::clone(&conn)));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    state: State,
    conn: Connection,
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
                    if let Ok(inflated) = zlib::inflate(&buffer) {
                        let message: MeetingServerMessage =
                            serde_json::from_slice(&inflated)?;

                        println!("got message: {:#?}", message);
                    } else {
                        tracing::warn!(
                            "could not inflate message buffer"
                        );
                    }
                }
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_frame) => {
                    disconnect(state, Arc::clone(&conn)).await;
                    // let _ =
                    //     outgoing_tx.send(Message::Close(frame)).await;
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

/*
async fn write(
    mut sender: SplitSink<WebSocket, Message>,
    state: State,
    conn: Connection,
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
*/
