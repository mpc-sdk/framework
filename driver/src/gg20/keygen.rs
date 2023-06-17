//! Key generation for GG20.
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{
    Keygen, ProtocolMessage, LocalKey,
};

use curv::elliptic::curves::secp256_k1::Secp256k1;
use round_based::{Msg, StateMachine};

use super::{Error, Result};
use crate::{
    Bridge, Parameters, Participant, ProtocolDriver, RoundBuffer,
    RoundMsg,
};
use mpc_relay_client::{EventStream, NetworkTransport, Transport};
use mpc_relay_protocol::{hex, SessionState};

type Message = Msg<<Keygen as StateMachine>::MessageBody>;

/// GG20 key generation.
pub struct KeyGenerator {
    bridge: Bridge<Message, KeygenDriver>,
}

impl KeyGenerator {
    /// Create a new GG20 key generator.
    pub fn new(
        transport: Transport,
        event_stream: EventStream,
        parameters: Parameters,
        session: SessionState,
    ) -> Result<Self> {
        let buffer = RoundBuffer::new_fixed(5, parameters.parties);
        let participant = Participant {
            public_key: transport.public_key().to_vec(),
            session,
        };
        let driver = KeygenDriver::new(parameters, participant)?;
        let bridge = Bridge {
            transport,
            event_stream,
            driver,
            buffer,
        };
        Ok(Self { bridge })
    }

    /// Run the key generation protocol.
    pub async fn execute(&mut self) -> Result<LocalKey<Secp256k1>> {
        Ok(self.bridge.execute().await.map_err(Box::from)?)
    }
}

/// GG20 keygen driver.
pub struct KeygenDriver {
    inner: Keygen,
    participant: Participant,
}

impl KeygenDriver {
    /// Create a key generator.
    pub fn new(
        parameters: Parameters,
        participant: Participant,
    ) -> Result<KeygenDriver> {
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

impl ProtocolDriver for KeygenDriver {
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
