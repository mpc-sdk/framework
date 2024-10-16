//! Generate ECDSA signatures compatible with Ethereum.
use crate::Result;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    RecoveryId, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::borrow::Cow;

pub use k256::ecdsa::Signature;

/// Type for a recoverable signature.
#[derive(Serialize, Deserialize)]
pub struct RecoverableSignature {
    /// Signature bytes.
    pub signature: Vec<u8>,
    /// Recovery identifier.
    pub recovery_id: u8,
}

impl From<(Signature, RecoveryId)> for RecoverableSignature {
    fn from(value: (Signature, RecoveryId)) -> Self {
        Self {
            signature: value.0.to_bytes().as_slice().to_vec(),
            recovery_id: value.1.into(),
        }
    }
}

/// Create a signer for ECDSA signatures.
pub struct EcdsaSigner<'a> {
    signing_key: Cow<'a, SigningKey>,
}

impl<'a> EcdsaSigner<'a> {
    /// Create a new signer.
    pub fn new(signing_key: Cow<'a, SigningKey>) -> Self {
        Self { signing_key }
    }

    /// Initialize a signing key from a byte slice.
    pub fn from_slice(signing_key: &[u8]) -> Result<SigningKey> {
        Ok(SigningKey::from_slice(signing_key)?)
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
    ) -> Result<(Signature, RecoveryId)> {
        Ok(self.signing_key.sign_recoverable(message)?)
    }

    /// Sign the given message prehash, returning a signature
    /// and recovery ID.
    pub fn sign_prehash_recoverable(
        &self,
        prehash: &[u8],
    ) -> Result<(Signature, RecoveryId)> {
        Ok(self.signing_key.sign_prehash_recoverable(prehash)?)
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verifying key for this signer.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Verify a message.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        Ok(self.verifying_key().verify(message, signature)?)
    }

    /// Sign a message for Ethereum first hashing the message
    /// with the Keccak256 digest.
    pub fn sign_eth(
        &self,
        message: &[u8],
    ) -> Result<(Signature, RecoveryId)> {
        let digest = Keccak256::new_with_prefix(message);
        Ok(self.signing_key.sign_digest_recoverable(digest)?)
    }

    /// Sign an Ethereum message.
    pub fn sign_eth_message<B: AsRef<[u8]>>(
        &self,
        message: B,
    ) -> Result<(Signature, RecoveryId)> {
        let digest = Self::hash_message(message);
        Ok(self.signing_key.sign_digest_recoverable(digest)?)
    }

    /// Recover the public key from a signature and recovery identifier.
    pub fn recover(
        message: &[u8],
        signature: RecoverableSignature,
    ) -> Result<VerifyingKey> {
        let recid = RecoveryId::try_from(signature.recovery_id)?;
        let signature = Signature::from_slice(&signature.signature)?;
        Ok(VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(message),
            &signature,
            recid,
        )?)
    }

    /// Hash a message according to [EIP-191] (version `0x01`).
    ///
    /// The final message is a UTF-8 string, encoded as follows:
    /// `"\x19Ethereum Signed Message:\n" + message.length + message`
    ///
    /// This message is then hashed using [Keccak-256](keccak256).
    ///
    /// [EIP-191]: https://eips.ethereum.org/EIPS/eip-191
    pub fn hash_message<T: AsRef<[u8]>>(message: T) -> impl Digest {
        const PREFIX: &str = "\x19Ethereum Signed Message:\n";

        let message = message.as_ref();
        let len = message.len();
        let len_string = len.to_string();

        let mut eth_message =
            Vec::with_capacity(PREFIX.len() + len_string.len() + len);
        eth_message.extend_from_slice(PREFIX.as_bytes());
        eth_message.extend_from_slice(len_string.as_bytes());
        eth_message.extend_from_slice(message);

        Keccak256::new_with_prefix(eth_message)
    }
}
