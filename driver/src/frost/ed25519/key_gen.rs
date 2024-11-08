//! Key generation for FROST Ed25519.
use async_trait::async_trait;
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, SessionId, SessionState};
use rand::rngs::OsRng;
use std::collections::BTreeSet;

use crate::{
    frost::{Error, Result},
    Bridge, Driver, ProtocolDriver, RoundInfo, RoundMsg,
};

use super::MessageOut;

/// FROST Ed25519 key generation driver.
pub struct KeyGenDriver {
    bridge: Bridge<FrostDriver>,
}

impl KeyGenDriver {
    /// Create a new CGGMP key generator.
    pub fn new(
        transport: Transport,
        session: SessionState,
        session_id: SessionId,
    ) -> Result<Self> {
        todo!();
    }
}

#[async_trait]
impl Driver for KeyGenDriver {
    type Error = Error;
    type Output = (KeyPackage, PublicKeyPackage);

    async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Self::Output>> {
        self.bridge.handle_event(event).await
    }

    async fn execute(&mut self) -> Result<()> {
        self.bridge.execute().await
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

/// FROST keygen driver.
struct FrostDriver {}

impl FrostDriver {
    /// Create a key generator.
    pub fn new(session_id: SessionId) -> Result<Self> {
        todo!();
    }
}

impl ProtocolDriver for FrostDriver {
    type Error = Error;
    type Message = RoundMsg<MessageOut>;
    type Output = (KeyPackage, PublicKeyPackage);

    fn round_info(&self) -> Result<RoundInfo> {
        todo!();
    }

    fn proceed(&mut self) -> Result<Vec<Self::Message>> {
        todo!();
    }

    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> Result<()> {
        todo!();
    }

    fn try_finalize_round(&mut self) -> Result<Option<Self::Output>> {
        todo!();
    }
}
