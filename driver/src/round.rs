use round_based::Msg;
use serde::Serialize;
use std::collections::HashMap;

/// Round number.
pub type RoundNumber = u16;

/// Wrapper for a round `Msg` that includes the round
/// number.
///
/// Used to ensure round messages are grouped together and
/// out of order messages can thus be handled correctly.
#[derive(Serialize)]
pub struct RoundMsg<O> {
    round: u16,
    sender: u16,
    receiver: Option<u16>,
    body: O,
}

impl<O> RoundMsg<O> {
    /// Convert a collection of round messages.
    pub fn from_round(
        round: u16,
        messages: Vec<Msg<O>>,
    ) -> Vec<Self> {
        messages
            .into_iter()
            .map(|m| RoundMsg {
                round,
                sender: m.sender,
                receiver: m.receiver,
                body: m.body,
            })
            .collect::<Vec<_>>()
    }
}

/// Buffers incoming messages.
pub struct RoundBuffer<I> {
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
            expected.insert(i + 1, messages_per_round);
        }
        Self {
            expected,
            messages: Default::default(),
        }
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
