//! Signature generation for FROST.
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use frost_ed25519::{
    aggregate,
    round1::{self, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Identifier, Signature, SigningPackage,
};
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, SessionId, SessionState};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU16;

use crate::{
    frost::{Error, Result},
    Bridge, Driver, ProtocolDriver, RoundInfo, RoundMsg,
};

use super::{KeyShare, ROUND_1, ROUND_2, ROUND_3, ROUND_4};

#[derive(Debug, Serialize, Deserialize)]
pub enum SignPackage {
    Round1(SigningCommitments),
    Round2(Option<SigningPackage>),
    Round3(SignatureShare),
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
        is_initiator: bool,
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
            session_id,
            party_number,
            signer,
            verifiers,
            is_initiator,
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
    is_initiator: bool,
    identifiers: Vec<Identifier>,
    id: Identifier,
    min_signers: u16,
    round_number: u8,
    key_share: KeyShare,
    message: Vec<u8>,
    nonces: Option<SigningNonces>,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    aggregator_signing_package: Option<SigningPackage>,
    aggregator_signing_package_ack: u16,
    signing_package: Option<SigningPackage>,
    signature_shares: BTreeMap<Identifier, SignatureShare>,
}

impl FrostDriver {
    /// Create a driver.
    pub fn new(
        session_id: SessionId,
        party_number: NonZeroU16,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
        is_initiator: bool,
        identifiers: Vec<Identifier>,
        min_signers: u16,
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
            is_initiator,
            identifiers,
            id,
            min_signers,
            round_number: ROUND_1,
            key_share,
            message,
            nonces: None,
            commitments: BTreeMap::new(),
            aggregator_signing_package: None,
            aggregator_signing_package_ack: 0,
            signing_package: None,
            signature_shares: BTreeMap::new(),
        })
    }
}

impl ProtocolDriver for FrostDriver {
    type Error = Error;
    type Message = RoundMsg<SignPackage, VerifyingKey>;
    type Output = Signature;

    fn round_info(&self) -> Result<RoundInfo> {
        let round_number = self.round_number;
        let is_echo = false;
        let can_finalize = match self.round_number {
            ROUND_2 => {
                self.commitments.len() == self.min_signers as usize
            }
            ROUND_3 => self.signing_package.is_some(),
            ROUND_4 => {
                self.signature_shares.len()
                    == self.min_signers as usize
            }
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
            ROUND_1 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                let (nonces, commitments) = round1::commit(
                    self.key_share.0.signing_share(),
                    &mut OsRng,
                );

                for (index, id) in self.identifiers.iter().enumerate()
                {
                    if id == &self.id {
                        continue;
                    }

                    let receiver =
                        NonZeroU16::new((index + 1) as u16).unwrap();
                    let message = RoundMsg {
                        round: NonZeroU16::new(
                            self.round_number.into(),
                        )
                        .unwrap(),
                        sender: self.signer.verifying_key().clone(),
                        receiver,
                        body: SignPackage::Round1(
                            commitments.clone(),
                        ),
                    };

                    messages.push(message);
                }

                self.nonces = Some(nonces);
                self.commitments.insert(self.id.clone(), commitments);

                self.round_number =
                    self.round_number.checked_add(1).unwrap();

                Ok(messages)
            }
            ROUND_2 => {
                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                // Initiator is the aggregator/coordinator, creates
                // the signing package and sends it to the other
                // participants.
                //
                // Other participants send None to drive
                // the protocol forward.
                let signing_package = if self.is_initiator {
                    let signing_package = SigningPackage::new(
                        self.commitments.clone(),
                        &self.message,
                    );
                    Some(signing_package)
                } else {
                    None
                };

                for (index, id) in self.identifiers.iter().enumerate()
                {
                    if id == &self.id {
                        continue;
                    }

                    let receiver =
                        NonZeroU16::new((index + 1) as u16).unwrap();
                    let message = RoundMsg {
                        round: NonZeroU16::new(
                            self.round_number.into(),
                        )
                        .unwrap(),
                        sender: self.signer.verifying_key().clone(),
                        receiver,
                        body: SignPackage::Round2(
                            signing_package.clone(),
                        ),
                    };

                    messages.push(message);
                }

                if self.is_initiator {
                    // Store the signing package in a temporary field
                    // which will be assigned to signing_package once
                    // we receive messages from all other participants
                    self.aggregator_signing_package = signing_package;
                }

                self.round_number =
                    self.round_number.checked_add(1).unwrap();

                Ok(messages)
            }
            ROUND_3 => {
                let nonces = self
                    .nonces
                    .take()
                    .ok_or(Error::Round3TooEarly)?;

                let signing_package = self
                    .signing_package
                    .as_ref()
                    .ok_or(Error::Round3TooEarly)?;

                let signature_share = round2::sign(
                    signing_package,
                    &nonces,
                    &self.key_share.0,
                )?;

                let mut messages =
                    Vec::with_capacity(self.identifiers.len() - 1);

                for (index, id) in self.identifiers.iter().enumerate()
                {
                    if id == &self.id {
                        continue;
                    }

                    let receiver =
                        NonZeroU16::new((index + 1) as u16).unwrap();
                    let message = RoundMsg {
                        round: NonZeroU16::new(
                            self.round_number.into(),
                        )
                        .unwrap(),
                        sender: self.signer.verifying_key().clone(),
                        receiver,
                        body: SignPackage::Round3(
                            signature_share.clone(),
                        ),
                    };

                    messages.push(message);
                }

                self.signature_shares
                    .insert(self.id.clone(), signature_share);

                self.round_number =
                    self.round_number.checked_add(1).unwrap();

                Ok(messages)
            }
            _ => Err(Error::InvalidRound(self.round_number)),
        }
    }

    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> Result<()> {
        let round_number = message.round.get() as u8;
        match round_number {
            ROUND_1 => match message.body {
                SignPackage::Round1(commitments) => {
                    let party_index = self
                        .verifiers
                        .iter()
                        .position(|v| v == &message.sender)
                        .ok_or(Error::SenderVerifier)?;
                    if let Some(id) =
                        self.identifiers.get(party_index)
                    {
                        self.commitments
                            .insert(id.clone(), commitments);
                        Ok(())
                    } else {
                        Err(Error::SenderIdentifier(
                            round_number,
                            party_index,
                        ))
                    }
                }
                _ => Err(Error::RoundPayload(round_number)),
            },
            ROUND_2 => match message.body {
                SignPackage::Round2(signing_package) => {
                    let party_index = self
                        .verifiers
                        .iter()
                        .position(|v| v == &message.sender)
                        .ok_or(Error::SenderVerifier)?;
                    if let Some(_) = self.identifiers.get(party_index)
                    {
                        // Signing package sent by the aggregator
                        // to other participants
                        if signing_package.is_some() {
                            self.signing_package = signing_package;
                        // Empty signing package sent by other
                        // participants to drive the protocol forward
                        } else {
                            self.aggregator_signing_package_ack += 1;
                            if self.aggregator_signing_package_ack
                                == self.min_signers - 1
                            {
                                self.signing_package = self
                                    .aggregator_signing_package
                                    .take();
                            }
                        }
                        Ok(())
                    } else {
                        Err(Error::SenderIdentifier(
                            round_number,
                            party_index,
                        ))
                    }
                }
                _ => Err(Error::RoundPayload(round_number)),
            },
            ROUND_3 => match message.body {
                SignPackage::Round3(signature_share) => {
                    let party_index = self
                        .verifiers
                        .iter()
                        .position(|v| v == &message.sender)
                        .ok_or(Error::SenderVerifier)?;
                    if let Some(id) =
                        self.identifiers.get(party_index)
                    {
                        self.signature_shares
                            .insert(id.clone(), signature_share);
                        Ok(())
                    } else {
                        Err(Error::SenderIdentifier(
                            round_number,
                            party_index,
                        ))
                    }
                }
                _ => Err(Error::RoundPayload(round_number)),
            },
            _ => Err(Error::InvalidRound(round_number)),
        }
    }

    fn try_finalize_round(&mut self) -> Result<Option<Self::Output>> {
        if self.round_number == ROUND_4
            && self.signature_shares.len()
                == self.min_signers as usize
        {
            let signing_package = self
                .signing_package
                .take()
                .ok_or(Error::Round4TooEarly)?;

            let group_signature = aggregate(
                &signing_package,
                &self.signature_shares,
                &self.key_share.1,
            )?;

            Ok(Some(group_signature))
        } else {
            Ok(None)
        }
    }
}
