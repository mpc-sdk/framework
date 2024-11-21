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
use polysig_protocol::{
    zlib, MeetingResponse, MeetingRequest,
};

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
    pub async fn send(&mut self, buffer: &[u8]) -> Result<()> {
        let deflated = zlib::deflate(buffer)?;
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
                        let message: MeetingRequest =
                            serde_json::from_slice(&inflated)?;
                        match message {
                            MeetingRequest::NewRoom {
                                owner_id,
                                slots,
                                data,
                            } => {
                                let conn_id = {
                                    let conn = conn.lock().await;
                                    conn.id
                                };
                                let mut state = state.write().await;
                                let meeting_id =
                                    state.meetings.new_meeting(
                                        owner_id, slots, conn_id,
                                        data,
                                    );

                                let mut socket = conn.lock().await;
                                let response = MeetingResponse::RoomCreated {
                                    meeting_id,
                                    owner_id,
                                };
                                let buffer =
                                    serde_json::to_vec(&response)?;
                                socket.send(&buffer).await?;
                            }
                            MeetingRequest::JoinRoom {
                                meeting_id,
                                user_id,
                                data,
                            } => {
                                let conn_id = {
                                    let conn = conn.lock().await;
                                    conn.id
                                };

                                let is_full = {
                                    let mut state =
                                        state.write().await;
                                    if let Some(meeting) = state
                                        .meetings
                                        .get_meeting_mut(&meeting_id)
                                    {
                                        meeting.join(
                                            user_id, conn_id, data,
                                        );
                                        meeting.is_full()
                                    } else {
                                        tracing::warn!(id = %meeting_id, "no meeting");
                                        false
                                    }
                                };

                                let result = if is_full {
                                    let mut state =
                                        state.write().await;
                                    if let Some(meeting) = state
                                        .meetings
                                        .remove_meeting(&meeting_id)
                                    {
                                        let mut participants =
                                            Vec::with_capacity(
                                                meeting.slots.len(),
                                            );
                                        let mut sockets =
                                            Vec::with_capacity(
                                                meeting.slots.len(),
                                            );
                                        for (user_id, value) in
                                            meeting.slots
                                        {
                                            let (conn_id, data) =
                                                value.unwrap();
                                            participants.push((
                                                user_id, data,
                                            ));
                                            sockets.push(conn_id);
                                        }

                                        Some((sockets, participants))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                if let Some((sockets, participants)) =
                                    result
                                {
                                    let message = MeetingResponse::RoomReady { participants };
                                    let buffer =
                                        serde_json::to_vec(&message)?;

                                    let state = state.read().await;
                                    for conn_id in sockets {
                                        if let Some(conn) = state
                                            .connections
                                            .get(&conn_id)
                                        {
                                            let mut conn =
                                                conn.lock().await;
                                            conn.send(&buffer)
                                                .await?;
                                        }
                                    }
                                }
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
