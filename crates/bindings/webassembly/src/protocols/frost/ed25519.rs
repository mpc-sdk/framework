//! FROST Ed25519 protocol.
use polysig_client::{
    frost::ed25519::{dkg, sign},
    SessionOptions,
};
use polysig_driver::{
    frost::ed25519::{
        self as frost, Participant,
        PartyOptions as ProtocolPartyOptions,
        SigningKey as ProtocolSigningKey,
        VerifyingKey as ProtocolVerifyingKey,
    },
    KeyShare,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Threshold key share for FROST Ed25519.
pub type ThresholdKeyShare = frost::KeyShare;

use super::core::frost_impl;

frost_impl!(FrostEd25519Protocol);
