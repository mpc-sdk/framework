//! Key generation for CGGMP.
use async_trait::async_trait;
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, Parameters, SessionState};
use rand::rngs::OsRng;
use round_based::Msg;

use super::{Error, Result};
use synedrion::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    make_key_gen_session,
    sessions::Session,
    CombinedMessage, KeyGenResult, ProductionParams, SchemeParams,
};

use crate::{Bridge, Driver, ProtocolDriver, RoundBuffer, RoundMsg};

/// Key share.
pub type KeyShare = synedrion::KeyShare<ProductionParams>;

type MessageOut =
    (VerifyingKey, VerifyingKey, CombinedMessage<Signature>);
type MessageIn = (VerifyingKey, CombinedMessage<Signature>);

/// CGGMP key generation.
pub struct KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
    bridge: Bridge<CggmpDriver<P>>,
}

impl<P> KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a new CGGMP key generator.
    pub fn new(
        transport: Transport,
        parameters: Parameters,
        session: SessionState,
        shared_randomness: &[u8],
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

        let buffer =
            RoundBuffer::new_fixed(4, parameters.parties - 1);

        let driver = CggmpDriver::new(
            /*
            parameters,
            party_number.into(),
            */
            shared_randomness,
            signer,
            verifiers,
        )?;
        let bridge = Bridge {
            transport,
            driver: Some(driver),
            buffer,
            session,
        };
        Ok(Self { bridge })
    }
}

#[async_trait]
impl<P> Driver for KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
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

impl<P> From<KeyGenDriver<P>> for Transport
where
    P: SchemeParams + 'static,
{
    fn from(value: KeyGenDriver<P>) -> Self {
        value.bridge.transport
    }
}

/// CGGMP keygen driver.
struct CggmpDriver<P>
where
    P: SchemeParams + 'static,
{
    inner:
        Session<KeyGenResult<P>, Signature, SigningKey, VerifyingKey>,
}

impl<P> CggmpDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a key generator.
    pub fn new(
        /*
        parameters: Parameters,
        party_number: u16,
        */
        shared_randomness: &[u8],
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
    ) -> Result<Self> {
        Ok(Self {
            inner: make_key_gen_session(
                &mut OsRng,
                shared_randomness,
                signer,
                &verifiers,
            )
            .map_err(|e| Error::LocalError(e.to_string()))?,
        })
    }
}

impl<P> ProtocolDriver for CggmpDriver<P>
where
    P: SchemeParams + 'static,
{
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

/*
fn make_signers(
    num_parties: usize,
) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| *signer.verifying_key())
        .collect::<Vec<_>>();
    (signers, verifiers)
}
*/
