//! Generate EdDSA signatures compatible with Solana.

use crate::Result;
use ed25519::signature::{Signer, Verifier};
use ed25519_dalek::{SecretKey, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::borrow::Cow;

/// Create a signer for EdDSA signatures.
pub struct EddsaSigner<'a> {
    signing_key: Cow<'a, SigningKey>,
    verifying_key: VerifyingKey,
}

impl<'a> EddsaSigner<'a> {
    /// Create a new signer.
    pub fn new(signing_key: Cow<'a, SigningKey>) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Initialize a signing key from a byte array.
    pub fn from_bytes(signing_key: &SecretKey) -> SigningKey {
        SigningKey::from_bytes(signing_key)
    }

    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Sign a message.
    pub fn sign<B: AsRef<[u8]>>(&self, message: B) -> Signature {
        let signer = DalekSigner {
            signing_key: self.signing_key.as_ref(),
        };
        signer.sign(message)
    }

    /// Verifying key for this signer.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Verify a message.
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &Signature,
    ) -> Result<()> {
        let verifier = DalekVerifier {
            verifying_key: self.verifying_key(),
        };
        verifier.verify(message, &signature)
    }
}

struct DalekSigner<'a, S>
where
    S: Signer<ed25519::Signature>,
{
    pub signing_key: &'a S,
}

impl<'a, S> DalekSigner<'a, S>
where
    S: Signer<ed25519::Signature>,
{
    pub fn sign<B: AsRef<[u8]>>(
        &self,
        message: B,
    ) -> ed25519::Signature {
        self.signing_key.sign(message.as_ref())
    }
}

struct DalekVerifier<'a, V> {
    pub verifying_key: &'a V,
}

impl<'a, V> DalekVerifier<'a, V>
where
    V: Verifier<ed25519::Signature>,
{
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &ed25519::Signature,
    ) -> Result<()> {
        Ok(self.verifying_key.verify(message.as_ref(), signature)?)
    }
}
