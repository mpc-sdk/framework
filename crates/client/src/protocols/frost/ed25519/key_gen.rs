//! Key generation for FROST Ed25519.
use crate::{
    protocols::{Bridge, Driver},
    Error, NetworkTransport, Result, Transport,
};
use async_trait::async_trait;
use polysig_protocol::{hex, Event, SessionState};

use polysig_driver::{
    frost::ed25519::{DkgDriver as FrostDriver, KeyShare},
    frost_ed25519::Identifier,
};

/// FROST Ed25519 key generation driver.
pub struct KeyGenDriver {
    bridge: Bridge<FrostDriver>,
}

impl KeyGenDriver {
    /// Create a new FROST key generator.
    pub fn new(
        transport: Transport,
        session: SessionState,
        max_signers: u16,
        min_signers: u16,
        identifiers: Vec<Identifier>,
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
            max_signers,
            min_signers,
            identifiers,
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
impl Driver for KeyGenDriver {
    type Output = KeyShare;

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

impl From<KeyGenDriver> for Transport {
    fn from(value: KeyGenDriver) -> Self {
        value.bridge.transport
    }
}
