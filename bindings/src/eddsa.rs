//! EdDSA signatures compatible with Solana.
use mpc_driver::eddsa;
use std::borrow::Cow;
use wasm_bindgen::prelude::{wasm_bindgen, JsError};

/// Signer for EdDSA.
#[wasm_bindgen]
pub struct EddsaSigner {
    inner: eddsa::EddsaSigner<'static>,
}

#[wasm_bindgen]
impl EddsaSigner {
    /// Create a new signer.
    #[wasm_bindgen(constructor)]
    pub fn new(signing_key: &[u8]) -> Result<EddsaSigner, JsError> {
        let signing_key: [u8; 32] = signing_key.try_into()?;
        let signing_key =
            eddsa::EddsaSigner::from_bytes(&signing_key);
        Ok(Self {
            inner: eddsa::EddsaSigner::new(Cow::Owned(signing_key)),
        })
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Result<(), JsError> {
        let result = self.inner.sign(message);
        todo!();
    }
}
