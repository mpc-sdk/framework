//! Binary encoding implementation.

use binary_stream::{
    futures::{Decodable, Encodable},
    Endian, Options,
};
use std::io::Result;

pub(crate) fn encoding_error(
    e: impl std::error::Error + Send + Sync + 'static,
) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// Default binary encoding options.
fn encoding_options() -> Options {
    Options {
        endian: Endian::Little,
        max_buffer_size: Some(1024 * 32),
    }
}

/// Encode to a binary buffer.
pub async fn encode(encodable: &impl Encodable) -> Result<Vec<u8>> {
    binary_stream::futures::encode(encodable, encoding_options())
        .await
}

/// Decode from a binary buffer.
pub async fn decode<T: Decodable + Default>(
    buffer: impl AsRef<[u8]>,
) -> Result<T> {
    binary_stream::futures::decode(
        buffer.as_ref(),
        encoding_options(),
    )
    .await
}

pub(crate) mod types {
    pub const NOOP: u8 = 0;
    pub const ERROR: u8 = 255;

    pub const HANDSHAKE_INITIATOR: u8 = 1;
    pub const HANDSHAKE_RESPONDER: u8 = 2;

    pub const HANDSHAKE_SERVER: u8 = 1;
    pub const HANDSHAKE_PEER: u8 = 2;

    pub const TRANSPARENT: u8 = 128;
    pub const OPAQUE: u8 = 129;

    pub const OPAQUE_SERVER: u8 = 1;
    pub const OPAQUE_PEER: u8 = 2;

    pub const SESSION_NEW: u8 = 1;
    pub const SESSION_CREATED: u8 = 2;
    pub const SESSION_READY_NOTIFY: u8 = 3;
    pub const SESSION_READY: u8 = 4;
    pub const SESSION_CONNECTION: u8 = 5;
    pub const SESSION_ACTIVE_NOTIFY: u8 = 6;
    pub const SESSION_ACTIVE: u8 = 7;
    pub const SESSION_CLOSE: u8 = 8;
    pub const SESSION_FINISHED: u8 = 9;

    pub const ENCODING_BLOB: u8 = 1;
    pub const ENCODING_JSON: u8 = 2;
}

mod v1;

pub use v1::VERSION;
