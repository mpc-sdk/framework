//! Taproot Schnorr signatures compatible with Bitcoin (BIP-340).
use anyhow::Error;
use mpc_driver::signers::schnorr::{self, Signature};
use napi::JsError;
use napi_derive::napi;
use std::borrow::Cow;

/// Signer for Schnorr.
#[napi]
pub struct SchnorrSigner {
    inner: schnorr::SchnorrSigner<'static>,
}

#[napi]
impl SchnorrSigner {
    /// Create a new signer.
    #[napi(constructor)]
    pub fn new(
        signing_key: Vec<u8>,
    ) -> Result<SchnorrSigner, JsError> {
        let signing_key =
            schnorr::SchnorrSigner::from_slice(&signing_key)
                .map_err(Error::new)?;
        Ok(Self {
            inner: schnorr::SchnorrSigner::new(Cow::Owned(
                signing_key,
            )),
        })
    }

    /// Generate a random signing key.
    #[napi]
    pub fn random() -> Vec<u8> {
        schnorr::SchnorrSigner::random()
            .to_bytes()
            .as_slice()
            .to_vec()
    }

    /// Sign a message.
    #[napi]
    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        let result = self.inner.sign(&message);
        result.to_bytes().as_slice().to_vec()
    }

    /// Attempt to sign the given message digest, returning a
    /// digital signature on success, or an error if something went wrong.
    #[napi]
    pub fn sign_prehash(
        &self,
        prehash: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        let result =
            self.inner.sign_prehash(&prehash).map_err(Error::new)?;
        Ok(result.to_bytes().as_slice().to_vec())
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
