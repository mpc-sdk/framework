//! Generate Schnorr signatures compatible with Bitcoin
//! Taproot (BIP 340).
use k256::schnorr::{
    signature::{Signer, Verifier},
    Error, Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;

/// Create a signer for Taproot BIP-340 Schnorr signatures.
pub struct SchnorrSigner<'a> {
    signing_key: &'a SigningKey,
}

impl<'a> SchnorrSigner<'a> {
    /// Create a new signer.
    pub fn new(signing_key: &'a SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    /// Sign a message.
    pub fn sign<B: AsRef<[u8]>>(&self, message: B) -> Signature {
        self.signing_key.sign(message.as_ref())
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
