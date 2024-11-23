//! Driver for the FROST Ed25519 protocol.
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};

mod dkg;
mod sign;

pub use dkg::DkgDriver;
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
pub type Signature = frost_secp256k1_tr::Signature;
