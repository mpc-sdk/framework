use super::{Connection, State};
use crate::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

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
    mut reader: mpsc::Receiver<Vec<u8>>,
    writer: broadcast::Sender<Vec<u8>>,
) -> Result<()> {
    while let Some(buffer) = reader.recv().await {
        println!("service got read message...");
        let reply = vec![2; 16];
        writer.send(reply)?;
    }

    Ok(())
}
