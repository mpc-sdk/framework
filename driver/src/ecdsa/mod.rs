//! Generate ECDSA signatures compatible with Ethereum.
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Error, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;

/// Create a signer for ECDSA signatures.
pub struct EcdsaSigner<'a> {
    signing_key: &'a SigningKey,
}

impl<'a> EcdsaSigner<'a> {
    /// Create a new signer.
    pub fn new(signing_key: &'a SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    /// Sign the given message, hashing it with the curve’s
    /// default digest function, and returning a signature
    /// and recovery ID.
    pub fn sign_recoverable(
        &self,
        message: &[u8],
    ) -> Result<(Signature, RecoveryId), Error> {
        self.signing_key.sign_recoverable(message)
    }

    /// Sign the given message prehash, returning a signature
    /// and recovery ID.
    pub fn sign_prehash_recoverable(
        &self,
        prehash: &[u8],
    ) -> Result<(Signature, RecoveryId), Error> {
        self.signing_key.sign_prehash_recoverable(prehash)
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
