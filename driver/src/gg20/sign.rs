//! GG20 message signing.
use mpc_relay_client::{Event, NetworkTransport, Transport};
use mpc_relay_protocol::{hex, SessionState, PartyNumber};
use round_based::{Msg, StateMachine};
use serde::{Deserialize, Serialize};

use super::{Error, Result};
use crate::{
    curv::{
        arithmetic::Converter,
        elliptic::curves::{Point, Secp256k1},
        BigInt,
    },
    gg_2020::{
        party_i::{verify, SignatureRecid},
        state_machine::{
            keygen::LocalKey,
            sign::{
                CompletedOfflineStage, OfflineProtocolMessage,
                OfflineStage, PartialSignature, SignManual,
            },
        },
    },
    Bridge, Parameters, ProtocolDriver, RoundBuffer, RoundMsg,
};

type Message = Msg<<OfflineStage as StateMachine>::MessageBody>;

/// Generated signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    /// The generated ECDSA signature.
    pub signature: SignatureRecid,
    /// The public key for the signature.
    pub public_key: Vec<u8>,
    /// Address generated from the public key.
    pub address: String,
}

/// GG20 participant generator.
pub struct ParticipantGenerator {
    bridge: Bridge<ParticipantDriver>,
}

impl ParticipantGenerator {
    /// Create a new GG20 participant generator.
    pub fn new(
        transport: Transport,
        session: SessionState,
        local_key_index: PartyNumber,
    ) -> Result<Self> {
        let buffer = RoundBuffer::new_fixed(1, (session.len() - 1) as u16);

        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver = ParticipantDriver::new(
            party_number.into(),
            local_key_index.into(),
        );
        let bridge = Bridge {
            transport,
            driver,
            buffer,
            session,
        };
        Ok(Self { bridge })
    }

    /// Handle an incoming event.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Vec<u16>>> {
        Ok(self
            .bridge
            .handle_event(event)
            .await
            .map_err(Box::from)?)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<()> {
        Ok(self.bridge.execute().await.map_err(Box::from)?)
    }
}

/// GG20 presign generator.
pub struct PreSignGenerator {
    bridge: Bridge<SignOfflineDriver>,
}

impl PreSignGenerator {
    /// Create a new GG20 key generator.
    pub fn new(
        transport: Transport,
        parameters: Parameters,
        session: SessionState,
        local_key: LocalKey<Secp256k1>,
        participants: Vec<u16>,
    ) -> Result<Self> {
        let buffer = RoundBuffer::new_fixed(6, parameters.threshold);
        let party_index = participants
            .iter()
            .position(|index| index == &local_key.i)
            .map(|pos| pos + 1)
            .ok_or_else(|| Error::LocalKeyNotParticipant)?
            as u16;
        let driver = SignOfflineDriver::new(
            party_index,
            participants,
            local_key,
        )?;
        let bridge = Bridge {
            transport,
            driver,
            buffer,
            session,
        };
        Ok(Self { bridge })
    }

    /// Handle an incoming event.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<CompletedOfflineStage>> {
        Ok(self
            .bridge
            .handle_event(event)
            .await
            .map_err(Box::from)?)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<()> {
        Ok(self.bridge.execute().await.map_err(Box::from)?)
    }
}

/// GG20 signature generator.
pub struct SignatureGenerator {
    bridge: Bridge<SignOnlineDriver>,
}

impl SignatureGenerator {
    /// Create a new GG20 key generator.
    pub fn new(
        transport: Transport,
        parameters: Parameters,
        session: SessionState,
        completed_offline_stage: CompletedOfflineStage,
        message: [u8; 32],
    ) -> Result<Self> {
        let buffer = RoundBuffer::new_fixed(1, parameters.threshold);

        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver = SignOnlineDriver::new(
            party_number.into(),
            completed_offline_stage,
            message,
        )?;

        let bridge = Bridge {
            transport,
            driver,
            buffer,
            session,
        };
        Ok(Self { bridge })
    }

    /// Handle an incoming event.
    pub async fn handle_event(
        &mut self,
        event: Event,
    ) -> Result<Option<Signature>> {
        Ok(self
            .bridge
            .handle_event(event)
            .await
            .map_err(Box::from)?)
    }

    /// Start running the protocol.
    pub async fn execute(&mut self) -> Result<()> {
        Ok(self.bridge.execute().await.map_err(Box::from)?)
    }
}

/// GG20 local key participant number exchange.
///
/// Broadcasts the party number index for a previously generated 
/// key share to other participants in a session.
///
/// This is required to determine the participants for a sign offline 
/// protocol.
struct ParticipantDriver {
    party_number: u16,
    participants: Vec<u16>,
    local_key_index: u16,
}

impl ParticipantDriver {
    /// Create a key participant driver.
    pub fn new(
        party_number: u16,
        local_key_index: u16,
    ) -> Self {
        Self {
            party_number,
            participants: vec![local_key_index],
            local_key_index,
        }
    }
}

impl ProtocolDriver for ParticipantDriver {
    type Error = Error;
    type Incoming = Msg<u16>;
    type Outgoing = RoundMsg<u16>;
    type Output = Vec<u16>;

    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> Result<()> {
        self.participants.push(message.body);
        Ok(())
    }

    fn proceed(&mut self) -> Result<Vec<Self::Outgoing>> {
        let messages = vec![Msg {
            sender: self.party_number,
            receiver: None,
            body: self.local_key_index,
        }];
        Ok(RoundMsg::from_round(1, messages))
    }

    fn finish(&mut self) -> Result<Self::Output> {
        Ok(self.participants.clone())
    }
}

/// Drive the offline signing stage.
struct SignOfflineDriver {
    inner: OfflineStage,
}

impl SignOfflineDriver {
    /// Create a sign offline driver.
    pub fn new(
        index: u16,
        participants: Vec<u16>,
        local_key: LocalKey<Secp256k1>,
    ) -> Result<SignOfflineDriver> {
        Ok(SignOfflineDriver {
            inner: OfflineStage::new(index, participants, local_key)?,
        })
    }
}

impl ProtocolDriver for SignOfflineDriver {
    type Error = Error;
    type Incoming = Message;
    type Outgoing = RoundMsg<OfflineProtocolMessage>;
    type Output = CompletedOfflineStage;

    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> Result<()> {
        self.inner.handle_incoming(message)?;
        Ok(())
    }

    fn proceed(&mut self) -> Result<Vec<Self::Outgoing>> {
        self.inner.proceed()?;
        let messages = self.inner.message_queue().drain(..).collect();
        let round = self.inner.current_round();
        Ok(RoundMsg::from_round(round, messages))
    }

    fn finish(&mut self) -> Result<Self::Output> {
        Ok(self.inner.pick_output().unwrap()?)

        /*
        let data = BigInt::from_bytes(&self.message);
        let (_sign, partial) = SignManual::new(
            data.clone(),
            completed_offline_stage.clone(),
        )?;
        Ok(OfflineResult {
            data,
            partial,
            completed_offline_stage,
        })
        */
    }
}

/// Drive the online signing stage.
struct SignOnlineDriver {
    party_number: u16,
    data: BigInt,
    public_key: Point<Secp256k1>,
    partial: PartialSignature,
    sign: SignManual,
    partials: Vec<PartialSignature>,
}

impl SignOnlineDriver {
    /// Create a sign online driver.
    pub fn new(
        party_number: u16,
        completed_offline_stage: CompletedOfflineStage,
        message: [u8; 32],
    ) -> Result<Self> {
        let data = BigInt::from_bytes(&message);
        let public_key = completed_offline_stage.public_key().clone();
        let (sign, partial) =
            SignManual::new(data.clone(), completed_offline_stage)?;
        Ok(Self {
            party_number,
            public_key,
            sign,
            partial,
            data,
            partials: vec![],
        })
    }
}

impl ProtocolDriver for SignOnlineDriver {
    type Error = Error;
    type Incoming = Msg<PartialSignature>;
    type Outgoing = RoundMsg<PartialSignature>;
    type Output = Signature;

    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> Result<()> {
        self.partials.push(message.body);
        Ok(())
    }

    fn proceed(&mut self) -> Result<Vec<Self::Outgoing>> {
        let messages = vec![Msg {
            sender: self.party_number,
            receiver: None,
            body: self.partial.clone(),
        }];
        Ok(RoundMsg::from_round(1, messages))
    }

    fn finish(&mut self) -> Result<Self::Output> {
        //let pk =
        //self.completed_offline_stage.public_key().clone();

        /*
        let (sign, _partial) = SignManual::new(
            data.clone(),
            self.offline.completed_offline_stage.clone(),
        )?;
        */

        let signature = self.sign.clone().complete(&self.partials)?;
        verify(&signature, &self.public_key, &self.data)
            .map_err(|_| Error::VerifySignature)?;

        let public_key = self.public_key.to_bytes(false).to_vec();
        let result = Signature {
            signature,
            address: crate::address(&public_key),
            public_key,
        };

        Ok(result)
    }
}
