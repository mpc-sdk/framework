//! Generate Schnorr signatures compatible with Bitcoin
//! Taproot (BIP 340).
use crate::Result;
use k256::schnorr::{
    signature::{hazmat::PrehashSigner, Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use std::borrow::Cow;

/// Create a signer for Taproot BIP-340 Schnorr signatures.
pub struct SchnorrSigner<'a> {
    signing_key: Cow<'a, SigningKey>,
}

impl<'a> SchnorrSigner<'a> {
    /// Create a new signer.
    pub fn new(signing_key: Cow<'a, SigningKey>) -> Self {
        Self { signing_key }
    }

    /// Initialize a signing key from a byte slice.
    pub fn from_slice(signing_key: &[u8]) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(signing_key)?)
    }

    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    /// Sign a message.
    pub fn sign<B: AsRef<[u8]>>(&self, message: B) -> Signature {
        self.signing_key.sign(message.as_ref())
    }

    /// Attempt to sign the given message digest, returning a
    /// digital signature on success, or an error if something went wrong.
    pub fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        Ok(self.signing_key.as_ref().sign_prehash(prehash)?)
    }

    /// Verifying key for this signer.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Verify a message.
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &Signature,
    ) -> Result<()> {
        Ok(self
            .verifying_key()
            .verify(message.as_ref(), signature)?)
    }
}
