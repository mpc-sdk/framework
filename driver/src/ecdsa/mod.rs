//! Generate ECDSA signatures compatible with Ethereum.
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Error, Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;

/// Create a signer for ECDSA signatures.
pub struct EcdsaSigner {}

impl EcdsaSigner {
    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    /// Sign a message.
    pub fn sign<B: AsRef<[u8]>>(
        signing_key: &SigningKey,
        message: B,
    ) -> Signature {
        signing_key.sign(message.as_ref())
    }

    /// Verify a message.
    pub fn verify<B: AsRef<[u8]>>(
        verifying_key: &VerifyingKey,
        message: B,
        signature: &Signature,
    ) -> Result<(), Error> {
        verifying_key.verify(message.as_ref(), signature)
    }
}
