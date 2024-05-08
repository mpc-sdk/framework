//! Key generation for CGGMP.
use async_trait::async_trait;
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, Parameters, SessionState};
use round_based::{Msg, StateMachine};
use serde::{Deserialize, Serialize};

use super::{Error, Result};
use synedrion::{
    ecdsa::{
        signature::{
            hazmat::{PrehashVerifier, RandomizedPrehashSigner},
            Keypair,
        },
        Signature, SigningKey, VerifyingKey,
    },
    sessions::Session,
    CombinedMessage, KeyGenResult, ProductionParams, SchemeParams,
};

use crate::{Bridge, Driver, ProtocolDriver, RoundBuffer, RoundMsg};

/// Key share.
pub type KeyShare = synedrion::KeyShare<ProductionParams>;

/// Type of the inner keygen driver.
type KeygenInner<
    P: SchemeParams + 'static,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: PrehashVerifier<Sig> + std::fmt::Debug + Clone + Ord,
> = Session<KeyGenResult<P>, Sig, Signer, Verifier>;

type MessageOut =
    (VerifyingKey, VerifyingKey, CombinedMessage<Signature>);
type MessageIn = (VerifyingKey, CombinedMessage<Signature>);

/// CGGMP key generation.
pub struct KeyGenDriver {
    bridge: Bridge<KeygenDriver>,
}

impl KeyGenDriver {
    /// Create a new CGGMP key generator.
    pub fn new(
        transport: Transport,
        parameters: Parameters,
        session: SessionState,
    ) -> Result<Self> {
        /*
        let buffer =
            RoundBuffer::new_fixed(4, parameters.parties - 1);

        let party_number = session
            .party_number(transport.public_key())
            .ok_or_else(|| {
                Error::NotSessionParticipant(hex::encode(
                    transport.public_key(),
                ))
            })?;

        let driver =
            KeygenDriver::new(parameters, party_number.into())?;
        let bridge = Bridge {
            transport,
            driver: Some(driver),
            buffer,
            session,
        };
        Ok(Self { bridge })
        */

        todo!();
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
}

impl From<KeyGenDriver> for Transport {
    fn from(value: KeyGenDriver) -> Self {
        value.bridge.transport
    }
}

/// CGGMP keygen driver.
struct KeygenDriver {
    inner: KeygenInner<
        ProductionParams,
        Signature,
        SigningKey,
        VerifyingKey,
    >,
}

impl KeygenDriver {
    /// Create a key generator.
    pub fn new(
        parameters: Parameters,
        party_number: u16,
    ) -> Result<KeygenDriver> {
        /*
        Ok(Self {
            inner: Keygen::new(
                party_number,
                parameters.threshold,
                parameters.parties,
            )?,
        })
        */

        todo!();
    }
}

impl ProtocolDriver for KeygenDriver {
    type Error = Error;
    type Incoming = Msg<MessageIn>;
    type Outgoing = RoundMsg<MessageOut>;
    type Output = KeyShare;

    fn handle_incoming(
        &mut self,
        message: Self::Incoming,
    ) -> Result<()> {
        /*
        tracing::info!(
            "keygen handle incoming (round = {}, sender = {})",
            self.inner.current_round(),
            message.sender,
        );
        self.inner.handle_incoming(message)?;
        Ok(())
        */
        todo!();
    }

    fn proceed(&mut self) -> Result<Vec<Self::Outgoing>> {
        /*
        self.inner.proceed()?;
        let messages = self.inner.message_queue().drain(..).collect();
        let round = self.inner.current_round();
        Ok(RoundMsg::from_round(round, messages))
        */

        todo!();
    }

    fn finish(mut self) -> Result<Self::Output> {
        // Ok(self.inner.pick_output().unwrap()?)
        todo!();
    }
}
