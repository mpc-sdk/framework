//! Key generation for GG20.
use round_based::{Msg, StateMachine};

use mpc_relay_client::{Event, NetworkTransport, Transport};
use mpc_relay_protocol::{hex, SessionState};

use super::{Error, Result};
use crate::{
    curv::elliptic::curves::secp256_k1::Secp256k1,
    gg_2020::state_machine::keygen::{
        Keygen, LocalKey, ProtocolMessage,
    },
    Bridge, Parameters, ProtocolDriver, RoundBuffer, RoundMsg,
};

/// GG20 key generation.
pub struct KeyGenerator {
    bridge: Bridge<KeygenDriver>,
}

impl KeyGenerator {
    /// Create a new GG20 key generator.
    pub fn new(
        transport: Transport,
        parameters: Parameters,
        session: SessionState,
    ) -> Result<Self> {
        let buffer =
            RoundBuffer::new_fixed(4, parameters.parties - 1);

        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver = KeygenDriver::new(parameters, party_number.into())?;
        let bridge = Bridge {
            transport,
            driver,
            buffer,
            session,
        };
        Ok(Self { bridge })
    }

    /// Handle an incoming event.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<LocalKey<Secp256k1>>> {
        Ok(self
            .bridge
            .handle_event(event)
            .await
            .map_err(Box::from)?)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<()> {
        Ok(self.bridge.execute().await.map_err(Box::from)?)
    }
}

/// GG20 keygen driver.
pub struct KeygenDriver {
    inner: Keygen,
}

impl KeygenDriver {
    /// Create a key generator.
    pub fn new(
        parameters: Parameters,
        party_number: u16,
    ) -> Result<KeygenDriver> {
        Ok(Self {
            inner: Keygen::new(
                party_number,
                parameters.threshold,
                parameters.parties,
            )?,
        })
    }
}

impl ProtocolDriver for KeygenDriver {
    type Error = Error;
    type Incoming = Msg<ProtocolMessage>;
    type Outgoing = RoundMsg<ProtocolMessage>;
    type Output = LocalKey<Secp256k1>;

    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> Result<()> {
        self.inner.handle_incoming(message)?;
        Ok(())
    }

    fn proceed(&mut self) -> Result<Vec<Self::Outgoing>> {
        self.inner.proceed()?;
        let messages = self.inner.message_queue().drain(..).collect();
        let round = self.inner.current_round();
        Ok(RoundMsg::from_round(round, messages))
    }

    fn finish(&mut self) -> Result<Self::Output> {
        Ok(self.inner.pick_output().unwrap()?)
    }
}
