//! Signature generation for CGGMP.
use crate::{
    protocols::{Bridge, Driver},
    Error, NetworkTransport, Result, Transport,
};
use async_trait::async_trait;
use mpc_protocol::{hex, Event, SessionState};

use mpc_driver::{
    cggmp::SignatureDriver as CggmpDriver,
    recoverable_signature::RecoverableSignature,
    synedrion::{
        ecdsa::{SigningKey, VerifyingKey},
        AuxInfo, KeyShare, PrehashedMessage, SchemeParams, SessionId,
    },
};

/// CGGMP signing driver.
pub struct SignatureDriver<P>
where
    P: SchemeParams + 'static,
{
    bridge: Bridge<CggmpDriver<P>>,
}

impl<P> SignatureDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a new CGGMP signature driver.
    pub fn new(
        transport: Transport,
        session: SessionState,
        session_id: SessionId,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
        key_share: &KeyShare<P, VerifyingKey>,
        aux_info: &AuxInfo<P, VerifyingKey>,
        prehashed_message: &PrehashedMessage,
    ) -> Result<Self> {
        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver = CggmpDriver::new(
            session_id,
            signer,
            verifiers,
            key_share,
            aux_info,
            prehashed_message,
        )?;

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
impl<P> Driver for SignatureDriver<P>
where
    P: SchemeParams + 'static,
{
    type Output = RecoverableSignature;

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

impl<P> From<SignatureDriver<P>> for Transport
where
    P: SchemeParams + 'static,
{
    fn from(value: SignatureDriver<P>) -> Self {
        value.bridge.transport
    }
}
