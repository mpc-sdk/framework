//! Key generation for CGGMP.
use crate::{
    protocols::{Bridge, Driver},
    NetworkTransport, Transport,
};
use async_trait::async_trait;
use mpc_protocol::{hex, Event, SessionState};

use super::{Error, Result};
use mpc_driver::{
    cggmp::KeyGenDriver as CggmpDriver,
    synedrion::{
        ecdsa::{SigningKey, VerifyingKey},
        AuxInfo, KeyShare, SchemeParams, SessionId,
    },
};

/// CGGMP key generation driver.
pub struct KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
    bridge: Bridge<CggmpDriver<P>>,
}

impl<P> KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a new driver.
    pub fn new(
        transport: Transport,
        session: SessionState,
        session_id: SessionId,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
    ) -> Result<Self> {
        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver = CggmpDriver::new(session_id, signer, verifiers)?;

        let bridge = Bridge {
            transport,
            driver: Some(driver),
            session,
            party_number,
        };
        Ok(Self { bridge })
    }
}

#[async_trait]
impl<P> Driver for KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
    type Output =
        (KeyShare<P, VerifyingKey>, AuxInfo<P, VerifyingKey>);

    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Self::Output>> {
        Ok(self.bridge.handle_event(event).await?)
    }

    async fn execute(&mut self) -> Result<()> {
        Ok(self.bridge.execute().await?)
    }

    fn into_transport(self) -> Transport {
        self.bridge.transport
    }
}

impl<P> From<KeyGenDriver<P>> for Transport
where
    P: SchemeParams + 'static,
{
    fn from(value: KeyGenDriver<P>) -> Self {
        value.bridge.transport
    }
}
