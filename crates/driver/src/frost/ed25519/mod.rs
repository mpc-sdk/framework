//! Driver for the FROST Ed25519 protocol.
use ed25519_dalek::{SigningKey, VerifyingKey};
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};

mod dkg;
mod sign;

pub use dkg::DkgDriver;
pub use sign::SignatureDriver;

/// Participant in the protocol.
pub type Participant = crate::Participant<SigningKey, VerifyingKey>;

/// Options for each party.
pub type PartyOptions = crate::PartyOptions<VerifyingKey>;

/// Key share for this protocol.
pub type KeyShare = (KeyPackage, PublicKeyPackage);
/// Signature for this protocol.
pub type Signature = frost_ed25519::Signature;
