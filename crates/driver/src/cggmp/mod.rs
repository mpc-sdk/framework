//! Driver for the CGGMP protocol.
use serde::{Deserialize, Serialize};
use synedrion::{
    bip32::DerivationPath,
    ecdsa::{self, SigningKey, VerifyingKey},
    MessageBundle, SchemeParams, ThresholdKeyShare,
};

use polysig_protocol::pem;

const TAG: &str = "CGGMP KEY SHARE";
const PEM_V1: u16 = 1;

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

/// Threshold key share encoded as a PEM.
///
/// The actual threshold key share struct internally
/// uses `BTreeMap` which when passed over the webassembly
/// bindings will be converted to a Javascript `Map` however
/// the `Map` type is not natively supported in `JSON.stringify`
/// and `JSON.parse` without implementing custom replacer and
/// reviver functions which is cumbersome.
///
/// Therefore, to make sharing threshold key shares across the
/// Javacript/Webassembly bindings more ergonomic we first encode
/// the key share to JSON and then encode as a PEM.
///
/// A version number is included to allow us to recognize changes
/// in the upstream library `ThresholdKeyShare` struct.
#[derive(Serialize, Deserialize)]
pub struct KeySharePem {
    /// CGGMP protocol version.
    pub version: u16,
    /// PEM-encoded key share contents.
    pub contents: String,
}

impl<P> TryFrom<&KeyShare<P>> for KeySharePem
where
    P: SchemeParams,
{
    type Error = polysig_protocol::Error;

    fn try_from(
        value: &KeyShare<P>,
    ) -> std::result::Result<Self, Self::Error> {
        let key_share = serde_json::to_vec(value)?;
        let key_share = pem::Pem::new(TAG, key_share);
        let key_share = pem::encode(&key_share);
        Ok(Self {
            version: PEM_V1,
            contents: key_share,
        })
    }
}

impl<P> TryFrom<&KeySharePem> for KeyShare<P>
where
    P: SchemeParams,
{
    type Error = polysig_protocol::Error;

    fn try_from(
        value: &KeySharePem,
    ) -> std::result::Result<Self, Self::Error> {
        let key_share = pem::parse(&value.contents)?;
        let key_share: KeyShare<P> =
            serde_json::from_slice(key_share.contents())?;
        Ok(key_share)
    }
}

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
