//! Key generation for FROST Ed25519.
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
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

use super::{KeyShare, ROUND_1, ROUND_2, ROUND_3};

#[derive(Debug, Serialize, Deserialize)]
enum DkgPackage {
    Round1(dkg::round1::Package),
    Round2(dkg::round2::Package),
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

        let driver = FrostDriver::new(
            session_id,
            party_number,
            max_signers,
            min_signers,
            identifiers,
            signer,
            verifiers,
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
    type Output = KeyShare;

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
    #[allow(dead_code)]
    session_id: SessionId,
    #[allow(dead_code)]
    party_number: NonZeroU16,
    max_signers: u16,
    min_signers: u16,
    identifiers: Vec<Identifier>,
    id: Identifier,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
    round_number: u8,
    round1_package: Option<dkg::round1::SecretPackage>,
    received_round1_packages:
        BTreeMap<Identifier, dkg::round1::Package>,

    round2_package: Option<dkg::round2::SecretPackage>,
    received_round2_packages:
        BTreeMap<Identifier, dkg::round2::Package>,
}

impl FrostDriver {
    /// Create a key generator.
    pub fn new(
        session_id: SessionId,
        party_number: NonZeroU16,
        max_signers: u16,
        min_signers: u16,
        identifiers: Vec<Identifier>,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
    ) -> Result<Self> {
        let party_index: usize = party_number.get() as usize;
        let self_index = party_index - 1;
        let id = *identifiers
            .get(self_index)
            .ok_or(Error::IndexIdentifier(party_index))?;

        Ok(Self {
            session_id,
            party_number,
            max_signers,
            min_signers,
            identifiers,
            id,
            signer,
            verifiers,
            round_number: ROUND_1,

            round1_package: None,
            received_round1_packages: BTreeMap::new(),

            round2_package: None,
            received_round2_packages: BTreeMap::new(),
        })
    }
}

impl ProtocolDriver for FrostDriver {
    type Error = Error;
    type Message = RoundMsg<DkgPackage, VerifyingKey>;
    type Output = (KeyPackage, PublicKeyPackage);

    fn round_info(&self) -> Result<RoundInfo> {
        let needs = self.identifiers.len() - 1;
        let round_number = self.round_number;
        let is_echo = false;
        let can_finalize = match self.round_number {
            ROUND_2 => self.received_round1_packages.len() == needs,
            ROUND_3 => self.received_round2_packages.len() == needs,
            _ => false,
        };
        Ok(RoundInfo {
            round_number,
            can_finalize,
            is_echo,
        })
    }

    fn proceed(&mut self) -> Result<Vec<Self::Message>> {
        match self.round_number {
            // Round 1 is a broadcast round, same package
            // is sent to all other participants
            ROUND_1 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let (private_package, public_package) = dkg::part1(
                    self.id.clone(),
                    self.max_signers,
                    self.min_signers,
                    &mut OsRng,
                )?;

                self.round1_package = Some(private_package);

                for (index, id) in self.identifiers.iter().enumerate()
                {
                    if id != &self.id {
                        let receiver =
                            NonZeroU16::new((index + 1) as u16)
                                .unwrap();

                        let message = RoundMsg {
                            round: NonZeroU16::new(
                                self.round_number.into(),
                            )
                            .unwrap(),
                            sender: self
                                .signer
                                .verifying_key()
                                .clone(),
                            receiver,
                            body: DkgPackage::Round1(
                                public_package.clone(),
                            ),
                        };

                        messages.push(message);
                    }
                }

                self.round_number =
                    self.round_number.checked_add(1).unwrap();

                Ok(messages)
            }
            // Round 2 is a p2p round, different package
            // for each of the other participants
            ROUND_2 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let round1_secret_package =
                    self.round1_package.take().unwrap();

                let (round2_secret_package, round2_packages) =
                    dkg::part2(
                        round1_secret_package,
                        &self.received_round1_packages,
                    )?;

                self.round2_package = Some(round2_secret_package);

                for (receiver_id, package) in round2_packages {
                    let index = self
                        .identifiers
                        .iter()
                        .position(|i| i == &receiver_id)
                        .unwrap();

                    let receiver =
                        NonZeroU16::new((index + 1) as u16).unwrap();

                    let message = RoundMsg {
                        round: NonZeroU16::new(
                            self.round_number.into(),
                        )
                        .unwrap(),
                        sender: self.signer.verifying_key().clone(),
                        receiver,
                        body: DkgPackage::Round2(package),
                    };

                    messages.push(message);
                }

                self.round_number =
                    self.round_number.checked_add(1).unwrap();

                Ok(messages)
            }
            _ => Ok(vec![]),
        }
    }

    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> Result<()> {
        let round_number = message.round.get() as u8;
        match round_number {
            ROUND_1 => {
                match message.body {
                    DkgPackage::Round1(package) => {
                        let party_index = self
                            .verifiers
                            .iter()
                            .position(|v| v == &message.sender)
                            .unwrap();
                        if let Some(id) =
                            self.identifiers.get(party_index)
                        {
                            self.received_round1_packages
                                .insert(id.clone(), package);

                            Ok(())
                        } else {
                            panic!("recevier could not locate identifier");
                        }
                    }
                    _ => panic!("round was received out of turn"),
                }
            }
            ROUND_2 => {
                match message.body {
                    DkgPackage::Round2(package) => {
                        let party_index = self
                            .verifiers
                            .iter()
                            .position(|v| v == &message.sender)
                            .unwrap();
                        if let Some(id) =
                            self.identifiers.get(party_index)
                        {
                            self.received_round2_packages
                                .insert(id.clone(), package);
                            Ok(())
                        } else {
                            panic!("recevier could not locate identifier");
                        }
                    }
                    _ => panic!("round was received out of turn"),
                }
            }
            _ => Err(Error::InvalidRound(round_number)),
        }
    }

    fn try_finalize_round(&mut self) -> Result<Option<Self::Output>> {
        if self.round_number == ROUND_3
            && self.received_round1_packages.len()
                == self.identifiers.len() - 1
            && self.received_round2_packages.len()
                == self.identifiers.len() - 1
        {
            let round2_secret_package =
                self.round2_package.take().unwrap();

            let result = dkg::part3(
                &round2_secret_package,
                &self.received_round1_packages,
                &self.received_round2_packages,
            )?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}
