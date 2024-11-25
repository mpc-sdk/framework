//! FROST Ed25519 protocol.
use anyhow::Error;
use napi::bindgen_prelude::Result;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use crate::protocols::types::{KeyShare, SessionOptions};

use polysig_driver::{
    self as driver, ed25519_dalek,
    frost::ed25519::{
        self, Participant, PartyOptions as ProtocolPartyOptions,
        SigningKey,
    },
};

use polysig_client::frost::ed25519::{dkg, sign};

/// Threshold key share for FROST Ed25519.
pub type ThresholdKeyShare = ed25519::KeyShare;

use super::core::frost_impl;

frost_impl!(FrostEd25519Protocol);

impl TryFrom<ThresholdKeyShare> for KeyShare {
    type Error = polysig_protocol::Error;

    fn try_from(
        value: ThresholdKeyShare,
    ) -> std::result::Result<Self, Self::Error> {
        let key_share: driver::KeyShare = (&value).try_into()?;
        Ok(key_share.into())
    }
}

impl TryFrom<KeyShare> for ThresholdKeyShare {
    type Error = polysig_protocol::Error;

    fn try_from(
        value: KeyShare,
    ) -> std::result::Result<Self, Self::Error> {
        let key_share: driver::KeyShare = value.into();
        Ok((&key_share).try_into()?)
    }
}

#[doc(hidden)]
#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Signature {
    pub bytes: Vec<u8>,
}

impl TryFrom<Signature> for ed25519::Signature {
    type Error = napi::Error;

    fn try_from(
        value: Signature,
    ) -> std::result::Result<Self, Self::Error> {
        todo!();
    }
}

impl TryFrom<ed25519::Signature> for Signature {
    type Error = napi::Error;

    fn try_from(
        value: ed25519::Signature,
    ) -> std::result::Result<Self, Self::Error> {
        todo!();
    }
}

#[doc(hidden)]
#[napi(object)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Identifier {
    pub bytes: Vec<u8>,
}

impl TryFrom<Identifier> for ed25519::Identifier {
    type Error = napi::Error;

    fn try_from(
        value: Identifier,
    ) -> std::result::Result<Self, Self::Error> {
        todo!();
    }
}

impl TryFrom<ed25519::Identifier> for Identifier {
    type Error = napi::Error;

    fn try_from(
        value: ed25519::Identifier,
    ) -> std::result::Result<Self, Self::Error> {
        todo!();
    }
}

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

#[doc(hidden)]
#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions {
    pub public_key: Vec<u8>,
    pub participants: Vec<Vec<u8>>,
    pub is_initiator: bool,
    pub verifiers: Vec<VerifyingKey>,
}

impl TryFrom<PartyOptions> for ed25519::PartyOptions {
    type Error = napi::Error;

    fn try_from(
        value: PartyOptions,
    ) -> std::result::Result<Self, Self::Error> {
        let mut verifiers = Vec::with_capacity(value.verifiers.len());
        for verifier in value.verifiers {
            verifiers.push(verifier.try_into()?);
        }
        Ok(polysig_driver::PartyOptions::new(
            value.public_key,
            value.participants,
            value.is_initiator,
            verifiers,
        )
        .map_err(Error::new)?)
    }
}
