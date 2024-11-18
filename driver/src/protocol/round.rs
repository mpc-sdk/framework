use mpc_protocol::{PartyNumber, RoundNumber};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Trait for round messages.
pub(crate) trait Round:
    Serialize + DeserializeOwned + Send + Sync
{
    /// Round number.
    fn round_number(&self) -> RoundNumber;

    /// Receiver for a message.
    fn receiver(&self) -> &PartyNumber;
}

/// Wrapper for a round `Msg` that includes the round
/// number.
///
/// Used to ensure round messages are grouped together and
/// out of order messages can thus be handled correctly.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RoundMsg<O, V>
where
    O: Send + Sync,
{
    pub(crate) round: RoundNumber,
    pub(crate) sender: V,
    pub(crate) receiver: PartyNumber,
    pub(crate) body: O,
}

impl<O, V> RoundMsg<O, V>
where
    O: Serialize + Send + Sync + DeserializeOwned,
    V: Serialize + Send + Sync + DeserializeOwned,
{
    /// Consume this message into the sender and body.
    pub fn into_body(self) -> (V, O) {
        (self.sender, self.body)
    }
}

impl<O, V> Round for RoundMsg<O, V>
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
