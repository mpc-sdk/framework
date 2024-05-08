use mpc_protocol::{PartyNumber, RoundNumber};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

/// Trait for round messages.
pub(crate) trait Round:
    Serialize + DeserializeOwned + Send + Sync
{
    /// Determine if this round includes a broadcast message.
    fn is_broadcast(&self) -> bool;

    /// Determine if this round includes a direct message.
    fn is_direct(&self) -> bool;

    /// Round number.
    fn round_number(&self) -> RoundNumber;

    /// Receiver for a peer to peer message.
    fn receiver(&self) -> Option<&PartyNumber>;
}

/// Wrapper for a round `Msg` that includes the round
/// number.
///
/// Used to ensure round messages are grouped together and
/// out of order messages can thus be handled correctly.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RoundMsg<O>
where
    O: Send + Sync,
{
    pub(crate) round: RoundNumber,
    pub(crate) sender: PartyNumber,
    pub(crate) receiver: Option<PartyNumber>,
    pub(crate) body: O,
    pub(crate) is_broadcast: bool,
    pub(crate) is_direct: bool,
}

impl<O> Round for RoundMsg<O>
where
    O: Serialize + Send + Sync + DeserializeOwned,
{
    fn is_broadcast(&self) -> bool {
        self.is_broadcast
    }

    fn is_direct(&self) -> bool {
        self.is_direct
    }

    fn round_number(&self) -> RoundNumber {
        self.round
    }

    fn receiver(&self) -> Option<&PartyNumber> {
        self.receiver.as_ref()
    }
}

/*
impl<O> RoundMsg<O>
where
    O: Send + Sync,
{
    /// Convert a collection of round messages.
    pub fn from_round(
        round: u16,
        messages: Vec<Msg<O>>,
    ) -> Vec<Self> {
        messages
            .into_iter()
            .map(|m| RoundMsg {
                round: RoundNumber::new(round).unwrap(),
                sender: PartyNumber::new(m.sender).unwrap(),
                receiver: m
                    .receiver
                    .map(|v| PartyNumber::new(v).unwrap()),
                body: m.body,
                is_broadcast: m.is_broadcast,
                is_direct: m.is_direct,
            })
            .collect::<Vec<_>>()
    }
}
*/

/// Buffers incoming messages.
#[derive(Debug)]
pub(crate) struct RoundBuffer<I> {
    /// Determines the number of messages expected
    /// for each round.
    expected: HashMap<RoundNumber, u16>,

    /// Received messages.
    messages: HashMap<RoundNumber, Vec<I>>,
}

impl<I> RoundBuffer<I> {
    /// Create a new round buffer with a fixed number
    /// of messages per round.
    pub fn new_fixed(rounds: u16, messages_per_round: u16) -> Self {
        let mut expected = HashMap::new();
        for i in 0..rounds {
            expected.insert(
                RoundNumber::new(i + 1).unwrap(),
                messages_per_round,
            );
        }
        Self {
            expected,
            messages: Default::default(),
        }
    }

    /// Number of rounds configured.
    pub fn len(&self) -> usize {
        self.expected.len()
    }

    /// Add a message to the buffer.
    pub fn add_message(&mut self, round: RoundNumber, message: I) {
        let messages = self.messages.entry(round).or_insert(vec![]);
        messages.push(message);
    }

    /// Determine if a round is ready to proceed.
    pub fn is_ready(&self, round: RoundNumber) -> bool {
        if let (Some(amount), Some(messages)) =
            (self.expected.get(&round), self.messages.get(&round))
        {
            messages.len() == *amount as usize
        } else {
            false
        }
    }

    /// Take the messages for a round.
    ///
    /// The caller must have already checked the round is
    /// ready by calling `is_ready()`.
    ///
    /// If this is called before a round is ready the returned
    /// value will be incomplete or empty if no messages have
    /// been received for the round.
    pub fn take(&mut self, round: RoundNumber) -> Vec<I> {
        if let Some(messages) = self.messages.remove(&round) {
            messages
        } else {
            vec![]
        }
    }
}
