//! Driver for the CGGMP protocol.
use synedrion::{
    bip32::DerivationPath,
    ecdsa::{self, SigningKey, VerifyingKey},
    MessageBundle, SchemeParams, ThresholdKeyShare,
};

mod aux_gen;
mod error;
mod helpers;
mod key_gen;
mod key_init;
mod key_refresh;
mod key_resharing;
mod sign;

pub use aux_gen::AuxGenDriver;
pub use error::Error;
pub use key_gen::KeyGenDriver;
pub use key_init::KeyInitDriver;
pub use key_refresh::KeyRefreshDriver;
pub use key_resharing::KeyResharingDriver;
pub use sign::SignatureDriver;

type MessageOut = MessageBundle<ecdsa::Signature>;

/// Key share.
pub type KeyShare<P> = ThresholdKeyShare<P, VerifyingKey>;

/// Result type for the CGGMP protocol.
pub type Result<T> = std::result::Result<T, Error>;

/// Participant in the CGGMP protocol.
pub type Participant = crate::Participant<SigningKey, VerifyingKey>;

/// Options for each party.
pub type PartyOptions = crate::PartyOptions<VerifyingKey>;

/// Derive a child key using the BIP32 algorithm.
pub fn derive_bip32<P>(
    key_share: &ThresholdKeyShare<P, VerifyingKey>,
    derivation_path: &DerivationPath,
) -> Result<ThresholdKeyShare<P, VerifyingKey>>
where
    P: SchemeParams + 'static,
{
    Ok(key_share.derive_bip32(derivation_path)?)
}
