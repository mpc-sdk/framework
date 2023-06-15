//! Key generation for GG20.
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
    Keygen, ProtocolMessage, LocalKey,
};

use curv::elliptic::curves::secp256_k1::Secp256k1;
use mpc_relay_protocol::hex;
use round_based::{Msg, StateMachine};

use super::{Error, Result};
use crate::{Parameters, Participant, ProtocolDriver, RoundMsg};

type Message = Msg<<Keygen as StateMachine>::MessageBody>;

/// GG20 keygen driver.
pub struct KeyGenerator {
    inner: Keygen,
    participant: Participant,
}

impl KeyGenerator {
    /// Create a key generator.
    pub fn new(
        parameters: Parameters,
        participant: Participant,
    ) -> Result<KeyGenerator> {
        let party_number = participant
            .session
            .party_number(&participant.public_key)
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    &participant.public_key,
                ))
            })? as u16;
        Ok(Self {
            inner: Keygen::new(
                party_number,
                parameters.threshold,
                parameters.parties,
            )?,
            participant,
        })
    }
}

impl ProtocolDriver for KeyGenerator {
    type Error = Error;
    type Incoming = Message;
    type Outgoing = RoundMsg<ProtocolMessage>;
    type Output = LocalKey<Secp256k1>;

    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> Result<()> {
        self.inner.handle_incoming(message)?;
        Ok(())
    }

    fn proceed(&mut self) -> Result<(u16, Vec<Self::Outgoing>)> {
        self.inner.proceed()?;
        let messages = self.inner.message_queue().drain(..).collect();
        let round = self.inner.current_round();
        let messages = RoundMsg::from_round(round, messages);
        Ok((round, messages))
    }

    fn finish(&mut self) -> Result<Self::Output> {
        Ok(self.inner.pick_output().unwrap()?)
    }
}
