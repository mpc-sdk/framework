use crate::event_loop::InternalMessage;
use polysig_protocol::{http::StatusCode, ResponseMessage};
use thiserror::Error;

/// Errors generated by the relay client.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated attempting to connect to
    /// the websocket server when the response is
    /// not a 101 switching protocols status code.
    #[error("{0} {1}")]
    ConnectError(StatusCode, String),

    /// Error generated by the server.
    #[error("{0} {1}")]
    ServerError(StatusCode, String),

    /// Error generated if the client expects a reply but none was received.
    #[error("server did not reply")]
    NoReply,

    /// Error generated attempting to handshake with a peer that
    /// already exists.
    #[error("peer already exists")]
    PeerAlreadyExists,

    /// Error generated attempting to handshake with a peer that
    /// already exists.
    #[error(
        "peer already exists, maybe peers are racing to connect"
    )]
    PeerAlreadyExistsMaybeRace,

    /// Error generated when a peer could not be found.
    #[error(r#"peer "{0}" not found "#)]
    PeerNotFound(String),

    /// Error generated when a node expects to be in the handshake
    /// protocol state.
    #[error("not handshake protocol state")]
    NotHandshakeState,

    /// Error generated when a node expects to be in the transport
    /// protocol state.
    #[error("not transport protocol state")]
    NotTransportState,

    /// Error generated when the wrong type of message is encountered
    /// during a peer to peer handshake.
    #[error("invalid peer handshake message")]
    InvalidPeerHandshakeMessage,

    /// Error generated when the client fails to write to the websocket.
    #[error("web socket failed to send")]
    WebSocketSend,

    /// Error generated when meeting identifiers are not unique.
    #[error("meeting identifiers must be unique")]
    MeetingIdentifiersNotUnique,

    /// Error generated when the meeting initiator does not exist
    /// in the list of meeting point identifiers.
    #[error("meeting initiator must exist in list of identifiers")]
    MeetingInitiatorNotExist,

    /// Error generated when the user's public key is not in the
    /// list of session participants.
    #[error("public key {0} is not a session participant")]
    NotSessionParticipant(String),

    #[cfg(feature = "cggmp")]
    /// Could not locate ack for key init phase.
    #[error("could not find an ACK for key init phase")]
    NoKeyInitAck,

    /// Javascript string error message.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    #[error("{0}")]
    JsString(String),

    /// Javascript value error message.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    #[error("{0}")]
    JsValue(polysig_protocol::serde_json::Value),

    /// Javascript error that could not be converted.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    #[error("unknown javascript error (type conversion failed)")]
    JsError,

    /// Error generated when the native client fails to reunite
    /// the stream and sink.
    #[error("stream and sink reunite failed")]
    StreamReunite,

    /// Generic boxed error.
    #[error(transparent)]
    Generic(
        #[from] Box<dyn std::error::Error + Send + Sync + 'static>,
    ),

    /// Error generated by input/output.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] polysig_protocol::Error),

    /// Error generated by the driver library.
    #[error(transparent)]
    Driver(#[from] polysig_driver::Error),

    /// Error generated by the noise protocol library.
    #[error(transparent)]
    Snow(#[from] polysig_protocol::snow::error::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    /// Error generated by the client websocket library.
    #[error(transparent)]
    Websocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Error generated sending a request over a channel.
    #[error(transparent)]
    RequestMpscSend(
        #[from] tokio::sync::mpsc::error::SendError<InternalMessage>,
    ),

    /// Error generated sending a response over a channel.
    #[error(transparent)]
    ResponseMpscSend(
        #[from] tokio::sync::mpsc::error::SendError<ResponseMessage>,
    ),

    #[cfg(feature = "frost-ed25519")]
    /// FROST library error.
    #[error(transparent)]
    FrostEd25519Core(#[from] polysig_driver::frost_ed25519::Error),

    #[cfg(feature = "cggmp")]
    /// CGGMP library error.
    #[error(transparent)]
    Cggmp(#[from] polysig_driver::cggmp::Error),

    #[cfg(feature = "frost-ed25519")]
    /// FROST library error.
    #[error(transparent)]
    FrostEd25519(#[from] polysig_driver::frost::Error),
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<wasm_bindgen::JsValue> for Error {
    fn from(value: wasm_bindgen::JsValue) -> Self {
        if let Some(s) = value.as_string() {
            Error::JsString(s)
        } else {
            match serde_wasm_bindgen::from_value::<
                polysig_protocol::serde_json::Value,
            >(value)
            {
                Ok(val) => Error::JsValue(val),
                Err(_) => Error::JsError,
            }
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(value: Error) -> Self {
        let s = value.to_string();
        wasm_bindgen::JsValue::from_str(&s)
    }
}
