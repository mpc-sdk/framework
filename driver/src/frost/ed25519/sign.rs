//! Signature generation for FROST.
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use frost_ed25519::{
    round1::{self, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Identifier, Signature,
};
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, SessionId, SessionState};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

use crate::{
    frost::{Error, Result},
    Bridge, Driver, ProtocolDriver, RoundInfo, RoundMsg,
};

use super::{KeyShare, ROUND_1, ROUND_2, ROUND_3};

#[derive(Debug, Serialize, Deserialize)]
pub enum SignPackage {
    Round1(SigningNonces, SigningCommitments),
    Round2(SignatureShare),
}

/// FROST signing driver.
pub struct SignatureDriver {
    bridge: Bridge<FrostDriver>,
}

impl SignatureDriver {
    /// Create a new FROST signature driver.
    pub fn new(
        transport: Transport,
        session: SessionState,
        session_id: SessionId,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
        identifiers: Vec<Identifier>,
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
            session_id,
            party_number,
            signer,
            verifiers,
            identifiers,
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
    type Error = Error;
    type Output = Signature;

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

impl From<SignatureDriver> for Transport {
    fn from(value: SignatureDriver) -> Self {
        value.bridge.transport
    }
}

/// FROST signature driver.
struct FrostDriver {
    session_id: SessionId,
    party_number: NonZeroU16,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
    identifiers: Vec<Identifier>,
    id: Identifier,
    key_share: KeyShare,
    message: Vec<u8>,
}

impl FrostDriver {
    /// Create a driver.
    pub fn new(
        session_id: SessionId,
        party_number: NonZeroU16,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
        identifiers: Vec<Identifier>,
        key_share: KeyShare,
        message: Vec<u8>,
    ) -> Result<Self> {
        let party_index: usize = party_number.get() as usize;
        let self_index = party_index - 1;
        let id = *identifiers
            .get(self_index)
            .ok_or(Error::IndexIdentifier(party_index))?;

        Ok(Self {
            session_id,
            party_number,
            signer,
            verifiers,
            identifiers,
            id,
            key_share,
            message,
        })
    }
}

impl ProtocolDriver for FrostDriver {
    type Error = Error;
    type Message = RoundMsg<SignPackage, VerifyingKey>;
    type Output = Signature;

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
