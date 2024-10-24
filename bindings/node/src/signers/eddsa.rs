//! EdDSA signatures compatible with Solana.
use anyhow::Error;
use mpc_driver::signers::eddsa::{self, Signature};
use napi::JsError;
use napi_derive::napi;
use std::borrow::Cow;

/// Signer for EdDSA.
#[napi]
pub struct EddsaSigner {
    inner: eddsa::EddsaSigner<'static>,
}

#[napi]
impl EddsaSigner {
    /// Create a new signer.
    #[napi(constructor)]
    pub fn new(signing_key: Vec<u8>) -> Result<EddsaSigner, JsError> {
        let signing_key: [u8; 32] =
            signing_key.as_slice().try_into().map_err(Error::new)?;
        let signing_key =
            eddsa::EddsaSigner::from_bytes(&signing_key);
        Ok(Self {
            inner: eddsa::EddsaSigner::new(Cow::Owned(signing_key)),
        })
    }

    /// Generate a random signing key.
    #[napi]
    pub fn random() -> Vec<u8> {
        eddsa::EddsaSigner::random().to_bytes().as_slice().to_vec()
    }

    /// Sign a message.
    #[napi]
    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        let result = self.inner.sign(&message);
        result.to_bytes().as_slice().to_vec()
    }

    /// Verifying key for this signer.
    #[napi(js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.inner.verifying_key().to_bytes().to_vec()
    }

    /// Verify a message.
    #[napi]
    pub fn verify(
        &self,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), JsError> {
        let signature: Signature =
            signature.as_slice().try_into().map_err(Error::new)?;
        Ok(self
            .inner
            .verify(&message, &signature)
            .map_err(Error::new)?)
    }
}
