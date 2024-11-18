//! Key generation for CGGMP.
use async_trait::async_trait;
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, SessionState};
use rand::rngs::OsRng;
use std::collections::BTreeSet;

use super::{Error, Result};
use synedrion::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    make_key_gen_session,
    sessions::{
        FinalizeOutcome, PreprocessedMessage, RoundAccumulator,
        Session,
    },
    AuxInfo, KeyGenResult, KeyShare, SchemeParams, SessionId,
};

use crate::{
    key_to_str, Bridge, Driver, ProtocolDriver, RoundInfo, RoundMsg,
};

use super::MessageOut;

/// CGGMP key generation driver.
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
        session: SessionState,
        session_id: SessionId,
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

        let driver = CggmpDriver::new(session_id, signer, verifiers)?;

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
impl<P> Driver for KeyGenDriver<P>
where
    P: SchemeParams + 'static,
{
    type Error = Error;
    type Output =
        (KeyShare<P, VerifyingKey>, AuxInfo<P, VerifyingKey>);

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
    session: Option<
        Session<
            KeyGenResult<P, VerifyingKey>,
            Signature,
            SigningKey,
            VerifyingKey,
        >,
    >,
    accum: Option<RoundAccumulator<Signature, VerifyingKey>>,
    cached_messages:
        Vec<PreprocessedMessage<Signature, VerifyingKey>>,
    key: VerifyingKey,
    verifiers: Vec<VerifyingKey>,
}

impl<P> CggmpDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a key generator.
    pub fn new(
        session_id: SessionId,
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
    ) -> Result<Self> {
        let verifiers_set =
            verifiers.clone().into_iter().collect::<BTreeSet<_>>();
        let session = make_key_gen_session(
            &mut OsRng,
            session_id,
            signer,
            &verifiers_set,
        )
        .map_err(|e| Error::LocalError(e.to_string()))?;

        let cached_messages = Vec::new();
        let key = session.verifier();
        let accum = session.make_accumulator();

        Ok(Self {
            session: Some(session),
            accum: Some(accum),
            cached_messages,
            key,
            verifiers,
        })
    }
}

impl<P> ProtocolDriver for CggmpDriver<P>
where
    P: SchemeParams + 'static,
{
    type Error = Error;
    type Message = RoundMsg<MessageOut, VerifyingKey>;
    type Output =
        (KeyShare<P, VerifyingKey>, AuxInfo<P, VerifyingKey>);

    fn round_info(&self) -> Result<RoundInfo> {
        let session = self.session.as_ref().unwrap();
        let accum = self.accum.as_ref().unwrap();
        super::helpers::round_info(session, accum)
    }

    fn proceed(&mut self) -> Result<Vec<Self::Message>> {
        let session = self.session.as_mut().unwrap();
        let accum = self.accum.as_mut().unwrap();
        super::helpers::proceed(
            session,
            accum,
            &self.verifiers,
            &mut self.cached_messages,
            &self.key,
        )
    }

    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> Result<()> {
        let session = self.session.as_mut().unwrap();
        let accum = self.accum.as_mut().unwrap();
        super::helpers::handle_incoming(session, accum, message)
    }

    fn try_finalize_round(&mut self) -> Result<Option<Self::Output>> {
        let session = self.session.take().unwrap();
        let accum = self.accum.take().unwrap();

        let key_str = key_to_str(&session.verifier());
        println!("{key_str}: finalizing the round");

        match session.finalize_round(&mut OsRng, accum).unwrap() {
            FinalizeOutcome::Success(result) => Ok(Some(result)),
            FinalizeOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                self.accum = Some(new_session.make_accumulator());
                self.session = Some(new_session);
                self.cached_messages = new_cached_messages;
                Ok(None)
            }
        }
    }
}
