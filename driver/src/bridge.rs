use mpc_relay_client::Transport;

use crate::ProtocolDriver;

/// Connects a network transport with a protocol driver.
pub struct Bridge<E, I, O, R> {
    transport: Transport,
    driver: Box<
        dyn ProtocolDriver<
            Error = E,
            Incoming = I,
            Outgoing = O,
            Output = R,
        >,
    >,
}
