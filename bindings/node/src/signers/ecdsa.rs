//! ECDSA signatures compatible with Ethereum.
use anyhow::Error;
use mpc_driver::signers::ecdsa::{
    self, RecoverableSignature, Signature,
};
use napi::bindgen_prelude::Env;
use napi::{JsError, JsUnknown};
use napi_derive::napi;
use std::borrow::Cow;

/// Signer for ECDSA.
#[napi]
pub struct EcdsaSigner {
    inner: ecdsa::EcdsaSigner<'static>,
}

#[napi]
impl EcdsaSigner {
    /// Create a new signer.
    #[napi(constructor)]
    pub fn new(signing_key: &[u8]) -> Result<EcdsaSigner, JsError> {
        let signing_key = ecdsa::EcdsaSigner::from_slice(signing_key)
            .map_err(Error::new)?;
        Ok(Self {
            inner: ecdsa::EcdsaSigner::new(Cow::Owned(signing_key)),
        })
    }

    /// Generate a random signing key.
    pub fn random() -> Vec<u8> {
        ecdsa::EcdsaSigner::random().to_bytes().as_slice().to_vec()
    }

    /// Sign the given message, hashing it with the curve’s
    /// default digest function, and returning a signature
    /// and recovery ID.
    #[napi(js_name = "signRecoverable")]
    pub fn sign_recoverable(
        &self,
        message: &[u8],
        env: Env,
    ) -> Result<JsUnknown, JsError> {
        let result = self
            .inner
            .sign_recoverable(message)
            .map_err(Error::new)?;
        let signature: RecoverableSignature = result.into();
        Ok(env.to_js_value(&signature)?)
    }

    /// Sign the given message prehash, returning a signature
    /// and recovery ID.
    #[napi(js_name = "signPrehashRecoverable")]
    pub fn sign_prehash_recoverable(
        &self,
        message: &[u8],
        env: Env,
    ) -> Result<JsUnknown, JsError> {
        let result = self
            .inner
            .sign_prehash_recoverable(message)
            .map_err(Error::new)?;
        let signature: RecoverableSignature = result.into();
        Ok(env.to_js_value(&signature).map_err(Error::new)?)
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let result = self.inner.sign(message);
        result.to_bytes().as_slice().to_vec()
    }

    /// Verifying key for this signer.
    #[napi(js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.inner.verifying_key().to_sec1_bytes().to_vec()
    }

    /// Verify a message.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), JsError> {
        let signature =
            Signature::from_slice(signature).map_err(Error::new)?;
        Ok(self
            .inner
            .verify(message, &signature)
            .map_err(Error::new)?)
    }

    /// Verify a prehash.
    #[napi(js_name = "verifyPrehash")]
    pub fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &[u8],
    ) -> Result<(), JsError> {
        let signature =
            Signature::from_slice(signature).map_err(Error::new)?;
        Ok(self
            .inner
            .verify_prehash(prehash, &signature)
            .map_err(Error::new)?)
    }

    /// Sign a message for Ethereum first hashing the message
    /// with the Keccak256 digest.
    #[napi(js_name = "signEth")]
    pub fn sign_eth(
        &self,
        message: &[u8],
        env: Env,
    ) -> Result<JsUnknown, JsError> {
        let result =
            self.inner.sign_eth(message).map_err(Error::new)?;
        let signature: RecoverableSignature = result.into();
        Ok(env.to_js_value(&signature)?)
    }

    /// Recover the public key from a signature and recovery identifier.
    pub fn recover(
        message: &[u8],
        signature: JsUnknown,
        env: Env,
    ) -> Result<Vec<u8>, JsError> {
        let signature: RecoverableSignature =
            env.from_js_value(signature)?;
        let verifying_key =
            ecdsa::EcdsaSigner::recover(message, signature)
                .map_err(Error::new)?;
        let verifying_key_bytes =
            verifying_key.to_sec1_bytes().to_vec();
        Ok(verifying_key_bytes)
    }

    /// Compute the Keccak256 digest of a message.
    pub fn keccak256(message: &[u8]) -> Vec<u8> {
        use mpc_driver::sha3::{Digest, Keccak256};
        let digest = Keccak256::new_with_prefix(message);
        let hash = digest.finalize();
        hash.to_vec()
    }
}
