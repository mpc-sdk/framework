//! Helper functions for working with static keys.
use crate::{
    constants::{PATTERN, PEM_PATTERN, PEM_PRIVATE, PEM_PUBLIC},
    snow::Keypair,
    Error, Result,
};
use pem::Pem;

/// Generate a keypair for the noise protocol using the
/// standard pattern.
pub fn generate_keypair() -> Result<Keypair> {
    let builder = snow::Builder::new(PATTERN.parse()?);
    Ok(builder.generate_keypair()?)
}

/// Encode a keypair into a PEM-encoded string.
pub fn encode_keypair(keypair: &Keypair) -> String {
    let pattern_pem = Pem::new(PEM_PATTERN, PATTERN.as_bytes());
    let public_pem = Pem::new(PEM_PUBLIC, keypair.public.clone());
    let private_pem = Pem::new(PEM_PRIVATE, keypair.private.clone());
    pem::encode_many(&[pattern_pem, public_pem, private_pem])
}

/// Decode from a PEM-encoded string into a keypair.
pub fn decode_keypair(keypair: impl AsRef<[u8]>) -> Result<Keypair> {
    let mut pems = pem::parse_many(keypair)?;
    if pems.len() == 3 {
        let (first, second, third) =
            (pems.remove(0), pems.remove(0), pems.remove(0));
        if (PEM_PATTERN, PEM_PUBLIC, PEM_PRIVATE)
            == (first.tag(), second.tag(), third.tag())
        {
            if first.into_contents() != PATTERN.as_bytes() {
                return Err(Error::PatternMismatch(
                    PATTERN.to_string(),
                ));
            }
            Ok(Keypair {
                public: second.into_contents(),
                private: third.into_contents(),
            })
        } else {
            Err(Error::BadKeypairPem)
        }
    } else {
        Err(Error::BadKeypairPem)
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_keypair, encode_keypair, generate_keypair};
    use crate::{
        Error, PATTERN, PEM_PATTERN, PEM_PRIVATE, PEM_PUBLIC, TAGLEN,
    };
    use anyhow::Result;
    use pem::Pem;

    #[test]
    fn encode_decode_keypair() -> Result<()> {
        let keypair = generate_keypair()?;
        let pem = encode_keypair(&keypair);
        let decoded = decode_keypair(&pem)?;
        assert_eq!(keypair.public, decoded.public);
        assert_eq!(keypair.private, decoded.private);
        Ok(())
    }

    #[test]
    fn decode_keypair_wrong_length() -> Result<()> {
        let public_pem = Pem::new("INVALID TAG", vec![0; 32]);
        let pem = pem::encode_many(&[public_pem]);
        let result = decode_keypair(&pem);
        assert!(matches!(result, Err(Error::BadKeypairPem)));
        Ok(())
    }

    #[test]
    fn decode_keypair_wrong_order() -> Result<()> {
        let pattern_pem = Pem::new(PEM_PATTERN, vec![0; 32]);
        let public_pem = Pem::new(PEM_PUBLIC, vec![0; 32]);
        let private_pem = Pem::new(PEM_PRIVATE, vec![0; 32]);
        let pem =
            pem::encode_many(&[pattern_pem, private_pem, public_pem]);
        let result = decode_keypair(&pem);
        assert!(matches!(result, Err(Error::BadKeypairPem)));
        Ok(())
    }

    #[test]
    fn decode_keypair_pattern_mismatch() -> Result<()> {
        let pattern_pem = Pem::new(PEM_PATTERN, vec![0; 32]);
        let public_pem = Pem::new(PEM_PUBLIC, vec![0; 32]);
        let private_pem = Pem::new(PEM_PRIVATE, vec![0; 32]);
        let pem =
            pem::encode_many(&[pattern_pem, public_pem, private_pem]);
        let result = decode_keypair(&pem);
        assert!(matches!(result, Err(Error::PatternMismatch(_))));
        Ok(())
    }

    #[test]
    fn noise_transport_encrypt_decrypt() -> Result<()> {
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
