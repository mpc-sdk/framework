use thiserror::Error;

/// Errors generated by the protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated when the user's public key is not in the
    /// list of session participants.
    #[error("public key {0} is not a session participant")]
    NotSessionParticipant(String),

    /// Error generated by the client library.
    #[error(transparent)]
    Client(#[from] mpc_client::Error),

    /// Driver library error.
    #[error(transparent)]
    Driver(#[from] Box<crate::Error>),

    /// FROST library error.
    #[error(transparent)]
    Frost(#[from] frost_ed25519::Error),
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(value: Error) -> Self {
        let s = value.to_string();
        wasm_bindgen::JsValue::from_str(&s)
    }
}