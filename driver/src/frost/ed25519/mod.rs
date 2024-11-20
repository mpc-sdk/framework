//! Driver for the FROST Ed25519 protocol.
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};

mod key_gen;
mod sign;

pub use key_gen::KeyGenDriver;
pub use sign::SignatureDriver;

/// Participant in the protocol.
pub type Participant = crate::Participant<
    ed25519_dalek::SigningKey,
    ed25519_dalek::VerifyingKey,
>;

/// Options for each party.
pub type PartyOptions =
    crate::PartyOptions<ed25519_dalek::VerifyingKey>;

/// Key share for this protocol.
pub type KeyShare = (KeyPackage, PublicKeyPackage);
/// Signature for this protocol.
pub type Signature = frost_ed25519::Signature;

const ROUND_1: u8 = 1;
const ROUND_2: u8 = 2;
const ROUND_3: u8 = 3;
