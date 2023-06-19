//! Key generation for GG20.
use async_trait::async_trait;
use mpc_protocol::{hex, Parameters, SessionState};
use mpc_relay_client::{Event, NetworkTransport, Transport};
use round_based::{Msg, StateMachine};

use super::{Error, Result};
use crate::{
    curv::elliptic::curves::secp256_k1::Secp256k1,
    gg_2020::state_machine::keygen::{
        Keygen, LocalKey, ProtocolMessage,
    },
    Bridge, Driver, ProtocolDriver, RoundBuffer, RoundMsg,
};

/// Key share.
pub type KeyShare = LocalKey<Secp256k1>;

/// GG20 key generation.
pub struct KeyGenDriver {
    bridge: Bridge<KeygenDriver>,
}

impl KeyGenDriver {
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

        let driver =
            KeygenDriver::new(parameters, party_number.into())?;
        let bridge = Bridge {
            transport,
            driver: Some(driver),
            buffer,
            session,
        };
        Ok(Self { bridge })
    }
}

#[async_trait]
impl Driver for KeyGenDriver {
    type Error = Error;
    type Output = LocalKey<Secp256k1>;

    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Self::Output>> {
        self.bridge.handle_event(event).await
    }

    async fn execute(&mut self) -> Result<()> {
        self.bridge.execute().await
    }
}

impl From<KeyGenDriver> for Transport {
    fn from(value: KeyGenDriver) -> Self {
        value.bridge.transport
    }
}

/// GG20 keygen driver.
struct KeygenDriver {
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

    fn finish(mut self) -> Result<Self::Output> {
        Ok(self.inner.pick_output().unwrap()?)
    }
}
