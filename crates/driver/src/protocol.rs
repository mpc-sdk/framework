//! Types for the protocol drivers.

use crate::{Error, Result};
use polysig_protocol::{hex, PartyNumber, RoundNumber};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "cggmp")]
pub use synedrion::{self, bip32, k256};

#[cfg(feature = "frost-ed25519")]
pub use frost_ed25519;

/// Information about the current found which
/// can be retrieved from a driver.
#[derive(Debug)]
pub struct RoundInfo {
    /// Whether the round is ready to be finalized.
    pub can_finalize: bool,
    /// Whether the round is an echo round.
    pub is_echo: bool,
    /// Round number.
    pub round_number: u8,
}

/// Trait for implementations that drive
/// protocol to completion.
pub trait ProtocolDriver {
    /// Error type for results.
    type Error: std::error::Error
        + std::fmt::Debug
        + Send
        + Sync
        + From<polysig_protocol::Error>
        + 'static;

    /// Outgoing message type.
    type Message: std::fmt::Debug + Round;

    /// Output when the protocol is completed.
    type Output;

    /// Handle an incoming message.
    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> std::result::Result<(), Self::Error>;

    /// Proceed to the next round.
    fn proceed(
        &mut self,
    ) -> std::result::Result<Vec<Self::Message>, Self::Error>;

    /// Information about the current round for the driver.
    fn round_info(
        &self,
    ) -> std::result::Result<RoundInfo, Self::Error>;

    /// Try to finalize a round if the protocol is completed
    /// the result is returned.
    ///
    /// Must check with `can_finalize()` first.
    fn try_finalize_round(
        &mut self,
    ) -> std::result::Result<Option<Self::Output>, Self::Error>;
}

/// Trait for round messages.
pub trait Round: Serialize + DeserializeOwned + Send + Sync {
    /// Round number.
    #[allow(dead_code)]
    fn round_number(&self) -> RoundNumber;

    /// Receiver for a message.
    fn receiver(&self) -> &PartyNumber;
}

/// Round message with additional meta data.
///
/// Used to ensure round messages are grouped together and
/// out of order messages can thus be handled correctly.
#[derive(Debug, Serialize, Deserialize)]
pub struct RoundMessage<O, V>
where
    O: Send + Sync,
{
    pub(crate) round: RoundNumber,
    pub(crate) sender: V,
    pub(crate) receiver: PartyNumber,
    pub(crate) body: O,
}

impl<O, V> RoundMessage<O, V>
where
    O: Serialize + Send + Sync + DeserializeOwned,
    V: Serialize + Send + Sync + DeserializeOwned,
{
    /// Consume this message into the sender and body.
    #[allow(dead_code)]
    pub fn into_body(self) -> (V, O) {
        (self.sender, self.body)
    }
}

impl<O, V> Round for RoundMessage<O, V>
where
    O: Serialize + Send + Sync + DeserializeOwned,
    V: Serialize + Send + Sync + DeserializeOwned,
{
    fn round_number(&self) -> RoundNumber {
        self.round
    }

    fn receiver(&self) -> &PartyNumber {
        &self.receiver
    }
}

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
    /// The initiator is responsible for disposing of a
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
