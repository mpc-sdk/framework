use k256::ecdsa::VerifyingKey;
use mpc_protocol::{PartyNumber, RoundNumber};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Trait for round messages.
pub(crate) trait Round:
    Serialize + DeserializeOwned + Send + Sync
{
    /// Round number.
    fn round_number(&self) -> RoundNumber;

    /// Sender of a message.
    fn sender(&self) -> &VerifyingKey;

    /// Receiver for a message.
    fn receiver(&self) -> &PartyNumber;
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
    pub(crate) sender: VerifyingKey,
    pub(crate) receiver: PartyNumber,
    pub(crate) body: O,
}

impl<O> Round for RoundMsg<O>
where
    O: Serialize + Send + Sync + DeserializeOwned,
{
    fn round_number(&self) -> RoundNumber {
        self.round
    }

    fn sender(&self) -> &VerifyingKey {
        &self.sender
    }

    fn receiver(&self) -> &PartyNumber {
        &self.receiver
    }
}
