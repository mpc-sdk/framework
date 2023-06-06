use snow::{HandshakeState, TransportState};

/// Enumeration of protocol states.
pub enum ProtocolState {
    /// Noise handshake state.
    Handshake(HandshakeState),
    /// Noise transport state.
    Transport(TransportState),
}
