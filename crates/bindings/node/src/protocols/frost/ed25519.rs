//! FROST Ed25519 protocol.
use anyhow::Error;
use napi::bindgen_prelude::Result;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use crate::protocols::types::{KeyShare, SessionOptions};

use polysig_driver::{
    self as driver, ed25519_dalek,
    frost::ed25519::{
        self as frost, Participant,
        PartyOptions as ProtocolPartyOptions, SigningKey,
    },
};

use polysig_client::frost::ed25519::{dkg, sign};

/// Threshold key share for FROST Ed25519.
pub type ThresholdKeyShare = frost::KeyShare;

use super::core::{frost_impl, frost_types};

frost_types!();
frost_impl!(FrostEd25519Protocol);

#[doc(hidden)]
#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyingKey {
    pub bytes: Vec<u8>,
}

impl TryFrom<VerifyingKey> for ed25519_dalek::VerifyingKey {
    type Error = napi::Error;

    fn try_from(
        value: VerifyingKey,
    ) -> std::result::Result<Self, Self::Error> {
        let bytes: [u8; 32] =
            value.bytes.as_slice().try_into().map_err(Error::new)?;
        Ok(ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(Error::new)?)
    }
}
