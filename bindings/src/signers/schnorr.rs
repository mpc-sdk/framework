//! Taproot Schnorr signatures compatible with Bitcoin (BIP-340).
use mpc_driver::schnorr::{self, Signature};
use std::borrow::Cow;
use wasm_bindgen::prelude::{wasm_bindgen, JsError, JsValue};

/// Signer for Schnorr.
#[wasm_bindgen]
pub struct SchnorrSigner {
    inner: schnorr::SchnorrSigner<'static>,
}

#[wasm_bindgen]
impl SchnorrSigner {
    /// Create a new signer.
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key: &[u8]) -> Result<SchnorrSigner, JsError> {
        let signing_key =
            schnorr::SchnorrSigner::from_slice(signing_key)?;
        Ok(Self {
            inner: schnorr::SchnorrSigner::new(Cow::Owned(
                signing_key,
            )),
        })
    }

    /// Generate a random signing key.
    pub fn random() -> Vec<u8> {
        schnorr::SchnorrSigner::random()
            .to_bytes()
            .as_slice()
            .to_vec()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let result = self.inner.sign(message);
        result.to_bytes().as_slice().to_vec()
    }

    /// Attempt to sign the given message digest, returning a
    /// digital signature on success, or an error if something went wrong.
    pub fn sign_prehash(
        &self,
        prehash: &[u8],
    ) -> Result<JsValue, JsError> {
        let result = self.inner.sign_prehash(prehash)?;
        Ok(serde_wasm_bindgen::to_value(
            &result.to_bytes().as_slice(),
        )?)
    }

    /// Verifying key for this signer.
    pub fn verifying_key(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(self.inner.verifying_key())?)
    }

    /// Verify a message.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<JsValue, JsError> {
        let signature: Signature = signature.try_into()?;
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.verify(message, &signature)?,
        )?)
    }
}
