use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension,
    },
    http::StatusCode,
    response::Response,
};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use std::{
    fmt,
    sync::{atomic::Ordering, Arc},
};
use tokio::sync::Mutex;

//use axum_macros::debug_handler;

use crate::{server::State, Result};
use polysig_protocol::{zlib, MeetingServerMessage};

pub type Connection = Arc<Mutex<WebSocketConnection>>;

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Identifier for the socket connection.
    pub(crate) id: u64,
    /// Write end of the socket.
    pub writer: SplitSink<WebSocket, Message>,
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
        let deflated = zlib::deflate(&buffer)?;
        self.writer.send(Message::Binary(deflated)).await?;
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

    let socket_state = Arc::clone(&state);
    Ok(ws.on_upgrade(move |socket| {
        let (ws_writer, ws_reader) = socket.split();

        async move {
            let socket_conn = {
                let mut writer = state.write().await;

                let id = writer.id.fetch_add(1, Ordering::SeqCst);
                let conn =
                    Arc::new(Mutex::new(WebSocketConnection {
                        id,
                        writer: ws_writer,
                    }));
                let socket_conn = Arc::clone(&conn);
                writer.connections.insert(id, conn);
                socket_conn
            };

            tokio::task::spawn(read(
                ws_reader,
                socket_state,
                socket_conn,
            ));
        }
    }))
}

async fn disconnect(state: State, conn: Connection) {
    let id = {
        let reader = conn.lock().await;
        reader.id
    };
    tracing::debug!("disconnect");
    let mut writer = state.write().await;
    writer.connections.remove(&id);
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

                        match message {
                            MeetingServerMessage::NewRoom {
                                owner_id,
                                slots,
                                data,
                            } => {
                                let mut state = state.write().await;
                                state.meetings.new_meeting(
                                    owner_id, slots, data,
                                );
                            }
                            MeetingServerMessage::JoinRoom {
                                meeting_id,
                                user_id,
                                data,
                            } => {
                                let mut state = state.write().await;
                                if let Some(meeting) = state
                                    .meetings
                                    .get_meeting_mut(&meeting_id)
                                {
                                    meeting.join(user_id, data);

                                    if meeting.is_full() {
                                        todo!("broadcast to all meeting participants");
                                    }
                                } else {
                                    tracing::warn!(id = %meeting_id, "no meeting");
                                }
                                // state
                                //     .meetings
                                //     .join_meeting(user_id, data);
                            }
                        }
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
