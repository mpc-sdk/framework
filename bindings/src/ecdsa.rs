//! ECDSA signatures compatible with Ethereum.
use mpc_driver::ecdsa;
use std::borrow::Cow;
use wasm_bindgen::prelude::{wasm_bindgen, JsError};

/// Signer for ECDSA.
#[wasm_bindgen]
pub struct EcdsaSigner {
    inner: ecdsa::EcdsaSigner<'static>,
}

#[wasm_bindgen]
impl EcdsaSigner {
    /// Create a new signer.
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key: &[u8]) -> Result<EcdsaSigner, JsError> {
        let signing_key =
            ecdsa::EcdsaSigner::from_slice(signing_key)?;
        Ok(Self {
            inner: ecdsa::EcdsaSigner::new(Cow::Owned(signing_key)),
        })
    }

    /// Sign a message.
    pub fn sign_recoverable(
        &self,
        message: &[u8],
    ) -> Result<(), JsError> {
        let result = self.inner.sign_recoverable(message)?;
        todo!();
    }

    /// Sign a message prehash.
    pub fn sign_prehash_recoverable(
        &self,
        message: &[u8],
    ) -> Result<(), JsError> {
        let result = self.inner.sign_prehash_recoverable(message)?;
        todo!();
    }
}
