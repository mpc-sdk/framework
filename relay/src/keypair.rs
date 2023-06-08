//! Helper functions for working with static keys.
use crate::{
    constants::{PATTERN, PEM_PRIVATE, PEM_PUBLIC},
    Error, Result, snow::Keypair,
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
    let public_pem = Pem::new(PEM_PUBLIC, keypair.public.clone());
    let private_pem = Pem::new(PEM_PRIVATE, keypair.private.clone());
    pem::encode_many(&[public_pem, private_pem])
}

/// Decode from a PEM-encoded string into a keypair.
pub fn decode_keypair(keypair: impl AsRef<[u8]>) -> Result<Keypair> {
    let mut pems = pem::parse_many(keypair)?;
    if pems.len() == 2 {
        let (first, second) = (pems.remove(0), pems.remove(0));
        if (PEM_PUBLIC, PEM_PRIVATE) == (first.tag(), second.tag()) {
            Ok(Keypair {
                public: first.into_contents(),
                private: second.into_contents(),
            })
        } else {
            Err(Error::BadKeypairPem)
        }
    } else {
        Err(Error::BadKeypairPem)
    }
}
