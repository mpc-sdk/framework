//! ECDSA signatures compatible with Ethereum.
use mpc_driver::signers::ecdsa::{
    self, RecoverableSignature, Signature,
};
use std::borrow::Cow;
use wasm_bindgen::prelude::{wasm_bindgen, JsError, JsValue};

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

    /// Generate a random signing key.
    pub fn random() -> Vec<u8> {
        ecdsa::EcdsaSigner::random().to_bytes().as_slice().to_vec()
    }

    /// Sign the given message, hashing it with the curve’s
    /// default digest function, and returning a signature
    /// and recovery ID.
    #[wasm_bindgen(js_name = "signRecoverable")]
    pub fn sign_recoverable(
        &self,
        message: &[u8],
    ) -> Result<JsValue, JsError> {
        let result = self.inner.sign_recoverable(message)?;
        let signature: RecoverableSignature = result.into();
        Ok(serde_wasm_bindgen::to_value(&signature)?)
    }

    /// Sign the given message prehash, returning a signature
    /// and recovery ID.
    #[wasm_bindgen(js_name = "signPrehashRecoverable")]
    pub fn sign_prehash_recoverable(
        &self,
        message: &[u8],
    ) -> Result<JsValue, JsError> {
        let result = self.inner.sign_prehash_recoverable(message)?;
        let signature: RecoverableSignature = result.into();
        Ok(serde_wasm_bindgen::to_value(&signature)?)
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let result = self.inner.sign(message);
        result.to_bytes().as_slice().to_vec()
    }

    /// Verifying key for this signer.
    #[wasm_bindgen(js_name = "verifyingKey")]
    pub fn verifying_key(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(self.inner.verifying_key())?)
    }

    /// Verify a message.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<JsValue, JsError> {
        let signature = Signature::from_slice(signature)?;
        Ok(serde_wasm_bindgen::to_value(
            &self.inner.verify(message, &signature)?,
        )?)
    }

    /// Sign a message for Ethereum first hashing the message
    /// with the Keccak256 digest.
    #[wasm_bindgen(js_name = "signEth")]
    pub fn sign_eth(
        &self,
        message: &[u8],
    ) -> Result<JsValue, JsError> {
        let result = self.inner.sign_eth(message)?;
        let signature: RecoverableSignature = result.into();
        Ok(serde_wasm_bindgen::to_value(&signature)?)
    }

    /// Recover the public key from a signature and recovery identifier.
    pub fn recover(
        message: &[u8],
        signature: JsValue,
    ) -> Result<JsValue, JsError> {
        let signature: RecoverableSignature =
            serde_wasm_bindgen::from_value(signature)?;
        let verifying_key =
            ecdsa::EcdsaSigner::recover(message, signature)?;
        Ok(serde_wasm_bindgen::to_value(&verifying_key)?)
    }
}
