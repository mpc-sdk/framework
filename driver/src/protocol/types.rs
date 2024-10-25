//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use crate::{
    k256::ecdsa::{SigningKey, VerifyingKey},
    Error, Result,
};
use mpc_protocol::{hex, Keypair, Parameters};

/// Participant in a protocol session.
#[derive(Clone)]
pub struct Participant {
    /// Signing key for this participant.
    signing_key: SigningKey,
    /// Options for this participant.
    party: PartyOptions,
}

impl Participant {
    /// Create a new participant.
    pub fn new(
        signing_key: SigningKey,
        party: PartyOptions,
    ) -> Result<Self> {
        if party
            .verifiers()
            .into_iter()
            .find(|v| v == &signing_key.verifying_key())
            .is_none()
        {
            return Err(Error::NotVerifyingParty);
        }
        Ok(Self { signing_key, party })
    }

    /// Participant signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Participant party information.
    pub fn party(&self) -> &PartyOptions {
        &self.party
    }
}

/// Options for a party participating in a protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions {
    /// Public key of this party.
    #[serde(with = "hex::serde")]
    public_key: Vec<u8>,
    /// Public keys of all participants including this one.
    participants: Vec<Vec<u8>>,
    /// Whether this party is the session initiator.
    ///
    /// The initiator is reponsible for disposing of a
    /// session once a protocol completes.
    is_initiator: bool,
    /// Index of the party in the participants list.
    party_index: usize,
    /// Verifying keys for all participants.
    verifiers: Vec<VerifyingKey>,
}

impl PartyOptions {
    /// Create new party participant options.
    pub fn new(
        public_key: Vec<u8>,
        participants: Vec<Vec<u8>>,
        is_initiator: bool,
        verifiers: Vec<VerifyingKey>,
    ) -> Result<Self> {
        let party_index = participants
            .iter()
            .position(|v| v == &public_key)
            .ok_or(Error::NotVerifyingParty)?;

        if participants.len() != verifiers.len() {
            return Err(Error::ParticipantVerifierLength(
                participants.len(),
                verifiers.len(),
            ));
        }

        Ok(Self {
            public_key,
            participants,
            is_initiator,
            party_index,
            verifiers,
        })
    }

    /// Public key of this participant.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Participant public keys.
    pub fn participants(&self) -> &[Vec<u8>] {
        self.participants.as_slice()
    }

    /// Index of this participant.
    pub fn party_index(&self) -> usize {
        self.party_index
    }

    /// Whether this party is the session initator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Participant verifying keys.
    pub fn verifiers(&self) -> &[VerifyingKey] {
        self.verifiers.as_slice()
    }
}

/*
/// Signature for different protocols.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Signature {
    /// Signature for the CGGMP protocol.
    ///
    /// Note that we must convert the `RecoveryId` to `u8`
    /// for serde support.
    #[cfg(feature = "cggmp")]
    Cggmp(ecdsa::Signature, u8),
}

#[cfg(feature = "cggmp")]
impl From<synedrion::RecoverableSignature> for Signature {
    fn from(value: synedrion::RecoverableSignature) -> Self {
        let (sig, recovery_id) = value.to_backend();
        Signature::Cggmp(sig, recovery_id.into())
    }
}

#[cfg(feature = "cggmp")]
impl TryFrom<Signature> for (ecdsa::Signature, RecoveryId) {
    type Error = crate::Error;

    fn try_from(value: Signature) -> Result<Self> {
        match value {
            Signature::Cggmp(backend_signature, recovery_id) => {
                let rec_id: RecoveryId = recovery_id.try_into()?;
                Ok((backend_signature, rec_id))
            }
        }
    }
}
*/

/// Generated key share.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyShare {
    /// Private key share information.
    pub private_key: PrivateKey,
    /// The public key.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// Address generated from the public key.
    pub address: String,
}

/// Key share variants by protocol.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateKey {
    /// Key share for the CGGMP protocol.
    #[cfg(all(feature = "cggmp", not(debug_assertions)))]
    Cggmp(crate::cggmp::KeyShare<crate::synedrion::ProductionParams>),
    /// Key share for the CGGMP protocol.
    #[cfg(all(feature = "cggmp", debug_assertions))]
    Cggmp(crate::cggmp::KeyShare<crate::synedrion::TestParams>),
}

#[cfg(all(feature = "cggmp", debug_assertions))]
impl From<crate::cggmp::KeyShare<crate::synedrion::TestParams>>
    for KeyShare
{
    fn from(
        local_key: crate::cggmp::KeyShare<
            crate::synedrion::TestParams,
        >,
    ) -> Self {
        let public_key = local_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Self {
            private_key: PrivateKey::Cggmp(local_key),
            address: crate::address(&public_key),
            public_key,
        }
    }
}

#[cfg(all(feature = "cggmp", not(debug_assertions)))]
impl From<crate::cggmp::KeyShare<crate::synedrion::ProductionParams>>
    for KeyShare
{
    fn from(
        local_key: crate::cggmp::KeyShare<
            crate::synedrion::ProductionParams,
        >,
    ) -> Self {
        let public_key = local_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        Self {
            private_key: PrivateKey::Cggmp(local_key),
            address: crate::address(&public_key),
            public_key,
        }
    }
}

/// Options for creating or joining a meeting point.
#[derive(Serialize, Deserialize)]
pub struct MeetingOptions {
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Server options.
    pub server: ServerOptions,
}

/// Server options.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOptions {
    /// URL for the server.
    pub server_url: String,
    /// Server public key.
    #[serde(with = "hex::serde")]
    pub server_public_key: Vec<u8>,
    /// Noise parameters pattern.
    pub pattern: Option<String>,
}

/// Options used to drive a session to completion.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOptions {
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Server options.
    pub server: ServerOptions,
    /// Parameters for key generation.
    pub parameters: Parameters,
}
