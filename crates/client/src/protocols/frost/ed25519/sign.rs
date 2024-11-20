//! Signature generation for FROST.
use async_trait::async_trait;
use mpc_driver::{
    frost::ed25519::{KeyShare, SignatureDriver as FrostDriver},
    frost_ed25519::{Identifier, Signature},
};

use crate::{
    protocols::{Bridge, Driver},
    Error, NetworkTransport, Result, Transport,
};
use mpc_protocol::{hex, Event, SessionState};

/// FROST signing driver.
pub struct SignatureDriver {
    bridge: Bridge<FrostDriver>,
}

impl SignatureDriver {
    /// Create a new FROST signature driver.
    pub fn new(
        transport: Transport,
        session: SessionState,
        identifiers: Vec<Identifier>,
        min_signers: u16,
        key_share: KeyShare,
        message: Vec<u8>,
    ) -> Result<Self> {
        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver = FrostDriver::new(
            party_number,
            identifiers,
            min_signers,
            key_share,
            message,
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
impl Driver for SignatureDriver {
    type Output = Signature;

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

impl From<SignatureDriver> for Transport {
    fn from(value: SignatureDriver) -> Self {
        value.bridge.transport
    }
}
