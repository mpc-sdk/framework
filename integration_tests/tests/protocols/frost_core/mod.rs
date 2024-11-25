use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub(crate) mod dkg;
pub(crate) mod sign;

pub fn make_signers(
    num_parties: usize,
) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| signer.verifying_key().clone())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

pub fn make_signing_message() -> Vec<u8> {
    let message = "this is the message that is sent out";
    message.as_bytes().to_vec()
}
