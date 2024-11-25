//! FROST protocol implementations.
use anyhow::Error;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::protocols::types::{
    KeyShare, Params, PartyOptions, RecoverableSignature,
    SessionOptions, ThresholdKeyShare, VerifyingKey,
};

pub(crate) mod core;

#[cfg(feature = "frost-ed25519")]
pub mod ed25519;
