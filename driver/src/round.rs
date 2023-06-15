use round_based::Msg;
use serde::Serialize;

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
