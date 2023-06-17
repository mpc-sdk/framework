use mpc_relay_client::{EventLoop, Transport};
use mpc_relay_protocol::SessionState;

use crate::{Result, RoundBuffer};

/// Phases for bridge communication.
pub enum BridgePhase<D> {
    /// Prepare sets up all server and peer handshakes
    /// and creating and connecting to a session.
    Prepare,
    /// Driver phase drives the protocol by exchanging
    /// messages between the peers in the context of
    /// the session.
    Driver(D),
}

/// Connects a network transport with a protocol driver.
pub struct Bridge<I, D> {
    pub(crate) transport: Transport,
    pub(crate) event_loop: EventLoop,
    pub(crate) phase: BridgePhase<D>,
    pub(crate) buffer: RoundBuffer<I>,
}

impl<I, D> Bridge<I, D> {
    /// Make all connections and create a session.
    pub async fn create_session(
        &mut self,
        session_participants: Vec<Vec<u8>>,
    ) -> Result<SessionState> {
        todo!("create session for protocol driver");
    }
    
    /// Drive the protocol to completion.
    pub async fn drive(&mut self, driver: D) -> Result<()> {
        self.phase = BridgePhase::Driver(driver);
        todo!("drive protocol driver to completion");
    }
}
