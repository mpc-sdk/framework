//! Generic signature generation for FROST.
use async_trait::async_trait;
use polysig_driver::ProtocolDriver;

use crate::{
    protocols::{Bridge, Driver},
    Result, Transport,
};
use polysig_protocol::{Event, PartyNumber, SessionState};

/// FROST signing driver.
pub struct SignatureDriver<D, O>
where
    D: ProtocolDriver,
{
    bridge: Bridge<D>,
    marker: std::marker::PhantomData<O>,
}

impl<D, O> SignatureDriver<D, O>
where
    D: ProtocolDriver,
{
    /// Create a new FROST signature driver.
    pub fn new(
        transport: Transport,
        session: SessionState,
        party_number: PartyNumber,
        driver: D,
    ) -> Self {
        let bridge = Bridge {
            transport,
            driver: Some(driver),
            session,
            party_number,
        };
        Self {
            bridge,
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<D, O> Driver for SignatureDriver<D, O>
where
    D: ProtocolDriver<Output = O> + Send + Sync,
    O: Send + Sync,
{
    type Output = O;

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

impl<D, O> From<SignatureDriver<D, O>> for Transport
where
    D: ProtocolDriver,
{
    fn from(value: SignatureDriver<D, O>) -> Self {
        value.bridge.transport
    }
}
