//! FROST Secp256k1 Taproot protocol.
use polysig_client::{
    frost::secp256k1_tr::{dkg, sign},
    SessionOptions,
};
use polysig_driver::{
    frost::secp256k1_tr::{
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

/// Threshold key share for FROST Secp256k1 Taproot.
pub type ThresholdKeyShare = frost::KeyShare;

use super::core::frost_impl;

frost_impl!(FrostSecp256K1TrProtocol);
