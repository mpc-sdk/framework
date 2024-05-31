//! Key generation for CGGMP.
use std::num::NonZeroU16;

use async_trait::async_trait;
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, Parameters, SessionState};
use rand::rngs::OsRng;

use super::{Error, Result};
use synedrion::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    make_key_gen_session,
    sessions::{
        FinalizeOutcome, PreprocessedMessage, RoundAccumulator,
        Session,
    },
    CombinedMessage, KeyGenResult, KeyShare, SchemeParams,
};

use crate::{key_to_str, Bridge, Driver, ProtocolDriver, RoundMsg};

type MessageOut =
    (VerifyingKey, VerifyingKey, CombinedMessage<Signature>);

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

        let driver = CggmpDriver::new(
            parameters,
            party_number.into(),
            shared_randomness,
            signer,
            verifiers,
        )?;

        let bridge = Bridge {
            transport,
            driver: Some(driver),
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
    type Output = KeyShare<P, VerifyingKey>;

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
    parameters: Parameters,
    party_number: u16,
    session: Option<
        Session<KeyGenResult<P>, Signature, SigningKey, VerifyingKey>,
    >,
    accum: Option<RoundAccumulator<Signature>>,
    cached_messages: Vec<PreprocessedMessage<Signature>>,
    key: VerifyingKey,
    verifiers: Vec<VerifyingKey>,
}

impl<P> CggmpDriver<P>
where
    P: SchemeParams + 'static,
{
    /// Create a key generator.
    pub fn new(
        parameters: Parameters,
        party_number: u16,
        shared_randomness: &[u8],
        signer: SigningKey,
        verifiers: Vec<VerifyingKey>,
    ) -> Result<Self> {
        let session = make_key_gen_session(
            &mut OsRng,
            shared_randomness,
            signer,
            &verifiers,
        )
        .map_err(|e| Error::LocalError(e.to_string()))?;

        let cached_messages = Vec::new();
        let key = session.verifier();
        let accum = session.make_accumulator();

        Ok(Self {
            parameters,
            party_number,
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
    type Message = RoundMsg<MessageOut>;
    type Output = KeyShare<P, VerifyingKey>;

    type Session = Option<
        Session<KeyGenResult<P>, Signature, SigningKey, VerifyingKey>,
    >;
    type Accumulator = Option<RoundAccumulator<Signature>>;
    type CachedMessages = Vec<PreprocessedMessage<Signature>>;

    fn can_finalize(&self) -> Result<bool> {
        // TODO: error conversion
        Ok(self
            .session
            .as_ref()
            .unwrap()
            .can_finalize(self.accum.as_ref().unwrap())
            .unwrap())
    }

    fn proceed(&mut self) -> Result<Vec<Self::Message>> {
        let mut outgoing = Vec::new();

        let session = self.session.as_mut().unwrap();
        let accum = self.accum.as_mut().unwrap();

        let destinations = session.message_destinations();
        let key_str = key_to_str(&session.verifier());

        println!(
            "{key_str}: *** starting round {:?} ***",
            session.current_round()
        );

        println!(
            "proceed was called {} {} {}",
            key_str,
            self.party_number,
            destinations.len(),
        );

        for destination in destinations.iter() {
            // In production usage, this will happen in a spawned task
            // (since it can take some time to create a message),
            // and the artifact will be sent back to the host task
            // to be added to the accumulator.
            let (message, artifact) = session
                .make_message(&mut OsRng, destination)
                .unwrap();

            println!(
                "{key_str}: sending a message to {}",
                key_to_str(destination)
            );

            // This will happen in a host task
            accum.add_artifact(artifact).unwrap();

            let sender = self
                .verifiers
                .iter()
                .position(|i| i == &self.key)
                .unwrap();

            let receiver = self
                .verifiers
                .iter()
                .position(|i| i == destination)
                .unwrap();

            let sender: NonZeroU16 =
                ((sender + 1) as u16).try_into()?;
            let receiver: NonZeroU16 =
                ((receiver + 1) as u16).try_into()?;
            let round: NonZeroU16 =
                (session.current_round().0 as u16).try_into()?;

            outgoing.push(RoundMsg {
                body: (self.key, *destination, message),
                sender,
                receiver,
                round,
            });
        }

        for preprocessed in self.cached_messages.drain(..) {
            // In production usage, this will happen in a spawned task.
            println!("{key_str}: applying a cached message");
            let result =
                session.process_message(preprocessed).unwrap();

            // This will happen in a host task.
            accum.add_processed_message(result).unwrap().unwrap();
        }

        Ok(outgoing)
    }

    fn handle_incoming(
        &mut self,
        message: Self::Message,
    ) -> Result<()> {
        let session = self.session.as_mut().unwrap();
        let accum = self.accum.as_mut().unwrap();
        if !session.can_finalize(accum).unwrap() {
            let key_str = key_to_str(&session.verifier());
            tracing::info!(
                "keygen handle incoming (round = {}, sender = {})",
                session.current_round().0,
                message.sender,
            );

            // This can be checked if a timeout expired, to see which nodes have not responded yet.
            let unresponsive_parties =
                session.missing_messages(accum).unwrap();
            assert!(!unresponsive_parties.is_empty());

            /*
            println!("{key_str}: waiting for a message");
            */

            let from = &message.body.0;
            let message = message.body.2.clone();
            // let (from, message) = rx.recv().await.unwrap();

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session
                .preprocess_message(accum, from, message)
                .unwrap();

            if let Some(preprocessed) = preprocessed {
                println!(
                    "{key_str}: applying a message from {}",
                    key_to_str(&from)
                );
                let result =
                    session.process_message(preprocessed).unwrap();

                // This will happen in a host task.
                accum.add_processed_message(result).unwrap().unwrap();
            }
        }

        Ok(())
    }

    fn try_finalize_round(&mut self) -> Result<Option<Self::Output>> {
        let session = self.session.take().unwrap();
        let accum = self.accum.take().unwrap();

        let key_str = key_to_str(&session.verifier());
        println!("{key_str}: finalizing the round");

        match session.finalize_round(&mut OsRng, accum).unwrap() {
            FinalizeOutcome::Success((result, _)) => Ok(Some(result)),
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
