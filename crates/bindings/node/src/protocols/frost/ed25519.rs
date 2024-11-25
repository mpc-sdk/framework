use anyhow::Error;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::protocols::types::{
    KeyShare, SessionOptions, ThresholdKeyShare,
};

use polysig_driver::frost::ed25519::{
    Participant, PartyOptions, SigningKey,
};

use super::core::frost_impl;

frost_impl!(FrostEd25519Protocol);
