mod native;

pub use native::NativeClient;

/// Options used to create a new websocket client.
pub struct ClientOptions {
    /// Client static keypair.
    pub keypair: snow::Keypair,
    /// Public key for the server to connect to.
    pub server_public_key: Vec<u8>,
    /// Whether to automatically perform handshake
    /// with the server once a connection is established.
    pub auto_handshake: bool,
}
