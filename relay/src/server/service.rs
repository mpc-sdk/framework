use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

use super::{Connection, State};
use crate::{
    decode, encode, ProtocolState, RequestMessage, ResponseMessage, Result,
};

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
        writer: broadcast::Sender<Vec<u8>>,
    ) {
        tokio::spawn(listen(
            Arc::clone(&self.state),
            Arc::clone(&conn),
            reader,
            writer,
        ));
    }
}

async fn listen(
    state: State,
    conn: Connection,
    mut read_channel: mpsc::Receiver<Vec<u8>>,
    write_channel: broadcast::Sender<Vec<u8>>,
) -> Result<()> {
    // FIXME: robust error handling with error reply to client
    while let Some(buffer) = read_channel.recv().await {
        let message: RequestMessage = decode(&buffer).await?;
        match message {
            RequestMessage::HandshakeInitiator(len, buf) => {
                let mut writer = conn.write().await;
                let (len, payload) = match &mut writer.state {
                    Some(ProtocolState::Handshake(responder)) => {
                        let mut reply = vec![0u8; 1024];
                        let mut read_buf = vec![0u8; 1024];
                        responder
                            .read_message(&buf[..len], &mut read_buf)?;
                        let len =
                            responder.write_message(&[], &mut reply)?;

                        (len, reply)
                    }
                    _ => todo!(),
                };

                let response =
                    ResponseMessage::HandshakeResponder(len, payload);
                let buffer = encode(&response).await?;
                write_channel.send(buffer)?;

                if let Some(ProtocolState::Handshake(state)) =
                    writer.state.take()
                {
                    let transport = state.into_transport_mode()?;
                    writer.state =
                        Some(ProtocolState::Transport(transport));
                } else {
                    unreachable!();
                }
            }
            RequestMessage::Noop => {}
        }
    }
    Ok(())
}
