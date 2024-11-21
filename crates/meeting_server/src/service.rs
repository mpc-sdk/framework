use axum::http::StatusCode;
use futures::StreamExt;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::IntervalStream;

use polysig_protocol::{
    channel::{decrypt_server_channel, encrypt_server_channel},
    decode, encode, hex, Encoding, HandshakeMessage, MeetingState,
    OpaqueMessage, ProtocolState, RequestMessage, ResponseMessage,
    ServerMessage, SessionState, TransparentMessage,
};

use crate::{server::State, websocket::Connection, Error, Result};

pub struct RelayService {
    state: State,
}

impl RelayService {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    /// Start listening for messages on a websocket.
    pub(crate) fn listen_socket(
        &self,
        conn: Connection,
        reader: mpsc::Receiver<Vec<u8>>,
    ) {
        tokio::spawn(listen(
            Arc::clone(&self.state),
            Arc::clone(&conn),
            reader,
        ));
    }
}

async fn listen(
    state: State,
    conn: Connection,
    mut read_channel: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    /*
    while let Some(buffer) = read_channel.recv().await {
        let message: RequestMessage = decode(&buffer).await?;
        if let Err(e) = handle_request(
            Arc::clone(&state),
            Arc::clone(&conn),
            message,
        )
        .await
        {
            if let Err(e) = handle_error(Arc::clone(&conn), e).await {
                tracing::error!("{}", e);
            }
        }
    }
    */
    Ok(())
}

async fn handle_request(
    state: State,
    conn: Connection,
    message: RequestMessage,
) -> Result<()> {
    todo!();
}

/// Send a message to a collection of peers.
async fn notify_peers(
    state: State,
    public_keys: Vec<Vec<u8>>,
    message: ServerMessage,
) -> Result<()> {
    todo!();
}

/// Handle a server error.
async fn handle_error(conn: Connection, error: Error) -> Result<()> {
    todo!();
    Ok(())
}

/// Send a response message to a client over the server channel.
async fn send_message(
    conn: Connection,
    message: &ServerMessage,
    broadcast: bool,
) -> Result<()> {
    todo!();
    Ok(())
}
