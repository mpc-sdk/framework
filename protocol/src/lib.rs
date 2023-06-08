//! Relay server protocol types, encoding and helper functions.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod constants;
mod error;
mod keypair;
mod protocol;

pub use constants::*;
pub use error::Error;
pub use keypair::*;
pub use protocol::*;

pub use hex;
pub use http;
pub use pem;
pub use snow;
pub use uuid;

/// Result type for the relay protocol.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use crate::{PATTERN, TAGLEN};

    #[tokio::test]
    async fn noise_transport_encrypt_decrypt() -> Result<()> {
        let builder_1 = snow::Builder::new(PATTERN.parse()?);
        let builder_2 = snow::Builder::new(PATTERN.parse()?);

        let keypair1 = builder_1.generate_keypair()?;
        let keypair2 = builder_2.generate_keypair()?;

        let mut initiator = builder_1
            .local_private_key(&keypair1.private)
            .remote_public_key(&keypair2.public)
            .build_initiator()?;

        let mut responder = builder_2
            .local_private_key(&keypair2.private)
            .remote_public_key(&keypair1.public)
            .build_responder()?;

        let (mut read_buf, mut first_msg, mut second_msg) =
            ([0u8; 1024], [0u8; 1024], [0u8; 1024]);

        // -> e
        let len = initiator.write_message(&[], &mut first_msg)?;

        // responder processes the first message...
        responder.read_message(&first_msg[..len], &mut read_buf)?;

        // <- e, ee
        let len = responder.write_message(&[], &mut second_msg)?;

        // initiator processes the response...
        initiator.read_message(&second_msg[..len], &mut read_buf)?;

        // NN handshake complete, transition into transport mode.
        let mut initiator = initiator.into_transport_mode()?;
        let mut responder = responder.into_transport_mode()?;

        let data = "this is the message that is sent out";
        let payload = data.as_bytes();

        let mut message = vec![0; payload.len() + TAGLEN];
        let len = initiator.write_message(&payload, &mut message)?;

        let payload = message;
        let mut message = vec![0; len];
        responder.read_message(&payload[..len], &mut message)?;

        let new_length = len - TAGLEN;
        message.truncate(new_length);

        let decoded = std::str::from_utf8(&message)?;
        assert_eq!(data, decoded);

        Ok(())
    }
}
