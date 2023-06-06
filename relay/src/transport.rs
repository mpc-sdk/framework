use crate::Result;

use binary_stream::{BinaryReader, BinaryWriter, Endian, Options};
use serde::{de::DeserializeOwned, Serialize};
use snow::{Builder, Keypair};
use std::io::Cursor;

const BUF_SIZE: usize = 1024;

/// Default binary encoding options.
fn encoding_options() -> Options {
    Options {
        endian: Endian::Little,
        max_buffer_size: Some(1024 * 32),
    }
}

/// Encode a serializable into a binary buffer.
pub fn encode<S>(payload: &S) -> Result<Vec<u8>>
where
    S: Serialize + ?Sized,
{
    let serialized = serde_json::to_vec(payload)?;
    let mut buffer = Vec::new();
    let mut stream = Cursor::new(&mut buffer);
    let mut writer = BinaryWriter::new(&mut stream, encoding_options());
    writer.write_u32(serialized.len() as u32)?;
    writer.write_bytes(&serialized)?;
    writer.flush()?;
    Ok(buffer)
}

/// Decode a binary buffer into a type.
pub fn decode<T>(mut buffer: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut stream = Cursor::new(&mut buffer);
    let mut reader = BinaryReader::new(&mut stream, encoding_options());
    let length = reader.read_u32()?;
    let serialized = reader.read_bytes(length as usize)?;
    let result: T = serde_json::from_slice(&serialized)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::constants::{PATTERN, TAGLEN};
    use anyhow::Result;

    #[test]
    fn snow_handshake_encode_decode() -> Result<()> {
        let mut builder_1 = snow::Builder::new(PATTERN.parse()?);
        let mut builder_2 = snow::Builder::new(PATTERN.parse()?);

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
        let payload = encode(data)?;

        let mut message = vec![0; payload.len() + TAGLEN];
        initiator.write_message(&payload, &mut message)?;

        let payload = message;
        let mut message = vec![0; payload.len() + TAGLEN];
        responder.read_message(&payload, &mut message)?;

        let decoded: String = decode(&message)?;

        assert_eq!(data, &decoded);

        Ok(())
    }
}
