//! Types passed across the Javascript/Webassembly boundary.
use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use mpc_protocol::{hex, Keypair, Parameters};

/// Participant in a protocol session.
#[derive(Clone)]
pub struct Participant<S, V> {
    /// Signing key for this participant.
    signing_key: S,
    /// Options for this participant.
    party: PartyOptions<V>,
}

impl<S, V> Participant<S, V>
where
    V: PartialEq + std::fmt::Debug,
{
    /// Create a new participant.
    pub fn new(
        signing_key: S,
        verifying_key: V,
        party: PartyOptions<V>,
    ) -> Result<Self> {
        if party
            .verifiers()
            .into_iter()
            .find(|v| *v == &verifying_key)
            .is_none()
        {
            return Err(Error::NotVerifyingParty);
        }
        Ok(Self { signing_key, party })
    }

    /// Participant signing key.
    pub fn signing_key(&self) -> &S {
        &self.signing_key
    }

    /// Participant party information.
    pub fn party(&self) -> &PartyOptions<V> {
        &self.party
    }
}

/// Options for a party participating in a protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartyOptions<V> {
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
    verifiers: Vec<V>,
}

impl<V> PartyOptions<V> {
    /// Create new party participant options.
    pub fn new(
        public_key: Vec<u8>,
        participants: Vec<Vec<u8>>,
        is_initiator: bool,
        verifiers: Vec<V>,
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
    pub fn verifiers(&self) -> &[V] {
        self.verifiers.as_slice()
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOptions {
    /// Keypair for the participant.
    pub keypair: Keypair,
    /// Server options.
    pub server: ServerOptions,
    /// Parameters for key generation.
    pub parameters: Parameters,
}
