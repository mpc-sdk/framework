//! Key resharing for CGGMP.
use crate::{
    protocols::{Bridge, Driver},
    NetworkTransport, Transport,
};
use async_trait::async_trait;
use polysig_protocol::{hex, Event, SessionState};

use super::{Error, Result};
use polysig_driver::{
    cggmp::KeyResharingDriver as CggmpDriver,
    synedrion::{
        ecdsa::{SigningKey, VerifyingKey},
        KeyResharingInputs, SchemeParams, SessionId,
        ThresholdKeyShare,
    },
};

/// CGGMP key resharing driver.
pub struct KeyResharingDriver<P>
where
    P: SchemeParams + 'static,
{
    bridge: Bridge<CggmpDriver<P>>,
}

impl<P> KeyResharingDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a new CGGMP refresh.
    pub fn new(
        transport: Transport,
        session: SessionState,
        session_id: SessionId,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
        inputs: KeyResharingInputs<P, VerifyingKey>,
    ) -> Result<Self> {
        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver =
            CggmpDriver::new(session_id, signer, verifiers, inputs)?;

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
impl<P> Driver for KeyResharingDriver<P>
where
    P: SchemeParams + 'static,
{
    type Output = ThresholdKeyShare<P, VerifyingKey>;

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

impl<P> From<KeyResharingDriver<P>> for Transport
where
    P: SchemeParams + 'static,
{
    fn from(value: KeyResharingDriver<P>) -> Self {
        value.bridge.transport
    }
}
