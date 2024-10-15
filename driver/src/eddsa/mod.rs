//! Generate EdDSA signatures compatible with Solana.

use ed25519::signature::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Create a signer for EdDSA signatures.
pub struct EddsaSigner {}

impl EddsaSigner {
    /// Generate a random private signing key.
    pub fn random() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Sign a message.
    pub fn sign<B: AsRef<[u8]>>(
        signing_key: &SigningKey,
        message: B,
    ) -> Signature {
        let signer = DalekSigner { signing_key };
        signer.sign(message)
    }

    /// Verify a message.
    pub fn verify<B: AsRef<[u8]>>(
        verifying_key: &VerifyingKey,
        message: B,
        signature: &Signature,
    ) -> Result<(), ed25519::Error> {
        let verifier = DalekVerifier { verifying_key };
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
    ) -> Result<(), ed25519::Error> {
        self.verifying_key.verify(message.as_ref(), signature)
    }
}
