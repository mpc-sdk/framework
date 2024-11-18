//! Key generation for FROST Ed25519.
use async_trait::async_trait;
use frost_ed25519::{
    keys::{dkg, KeyPackage, PublicKeyPackage},
    Identifier,
};
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, SessionId, SessionState};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, num::NonZeroU16};

use crate::{
    frost::{Error, Result},
    Bridge, Driver, ProtocolDriver, RoundInfo, RoundMsg,
};

type MessageOut = RoundPackage;

#[derive(Serialize, Deserialize)]
pub(crate) enum RoundPackage {
    Round1(dkg::round1::Package),
}

/// FROST Ed25519 key generation driver.
pub struct KeyGenDriver {
    bridge: Bridge<FrostDriver>,
}

impl KeyGenDriver {
    /// Create a new FROST key generator.
    pub fn new(
        transport: Transport,
        session: SessionState,
        session_id: SessionId,
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
            session_id,
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
struct FrostDriver {
    session_id: SessionId,
    party_number: NonZeroU16,
    max_signers: u16,
    min_signers: u16,
    identifiers: Vec<Identifier>,
    round_number: NonZeroU16,
    round1_packages: BTreeMap<Identifier, dkg::round1::SecretPackage>,
    received_round1_packages:
        BTreeMap<Identifier, dkg::round1::Package>,
}

impl FrostDriver {
    /// Create a key generator.
    pub fn new(
        session_id: SessionId,
        party_number: NonZeroU16,
        max_signers: u16,
        min_signers: u16,
        identifiers: Vec<Identifier>,
    ) -> Result<Self> {
        Ok(Self {
            session_id,
            party_number,
            max_signers,
            min_signers,
            identifiers,
            round_number: NonZeroU16::new(1),
            round1_packages: BTreeMap::new(),
            received_round1_packages: BTreeMap::new(),
        })
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
        match self.round_number {
            1 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let party_index: usize = self.party_number.into();
                let self_index = party_index - 1;
                let self_id =
                    self.identifiers.get(self_index).unwrap();

                for (index, id) in self.identifiers.iter().enumerate()
                {
                    let (private_package, public_package) =
                        dkg::part1(
                            id.clone(),
                            self.max_signers,
                            self.min_signers,
                            &mut OsRng,
                        )?;
                    self.round1_packages
                        .insert(id.clone(), private_package);

                    if id != self_id {
                        let receiver = NonZeroU16::new(index + 1);
                        let message = RoundMsg {
                            round,
                            receiver,
                            body: RoundPackage::Round1(
                                public_package,
                            ),
                        };
                    }
                }

                self.round_number += 1;
                return Ok(messages);
            }
            _ => todo!("handle other rounds"),
        }
        /*
         */
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