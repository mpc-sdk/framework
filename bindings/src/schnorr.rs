//! Taproot Schnorr signatures compatible with Bitcoin (BIP-340).
use mpc_driver::schnorr;
use std::borrow::Cow;
use wasm_bindgen::prelude::{wasm_bindgen, JsError};

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
    pub fn sign(&self, message: &[u8]) -> Result<(), JsError> {
        let result = self.inner.sign(message);
        todo!();
    }

    /// Sign a prehashed message.
    pub fn sign_prehash(
        &self,
        prehash: &[u8],
    ) -> Result<(), JsError> {
        let result = self.inner.sign_prehash(prehash);
        todo!();
    }
}
