//! Key generation for CGGMP.
use std::num::NonZeroU16;

use async_trait::async_trait;
use mpc_client::{Event, NetworkTransport, Transport};
use mpc_protocol::{hex, Parameters, SessionState};
use rand::rngs::OsRng;
use round_based::Msg;

use super::{Error, Result};
use synedrion::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    make_key_gen_session,
    sessions::{
        FinalizeOutcome, PreprocessedMessage, RoundAccumulator,
        Session,
    },
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
    session:
        Session<KeyGenResult<P>, Signature, SigningKey, VerifyingKey>,

    cached_messages: Vec<PreprocessedMessage<Signature>>,
    key: VerifyingKey,
    accum: RoundAccumulator<Signature>,
    verifiers: Vec<VerifyingKey>,
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
            session,
            cached_messages,
            key,
            accum,
            verifiers,
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
        tracing::info!(
            "keygen handle incoming (round = {}, sender = {})",
            self.session.current_round().0,
            message.sender,
        );

        for preprocessed in self.cached_messages.drain(..) {
            // In production usage, this will happen in a spawned task.
            // println!("{key_str}: applying a cached message");
            let result =
                self.session.process_message(preprocessed).unwrap();

            // This will happen in a host task.
            self.accum
                .add_processed_message(result)
                .unwrap()
                .unwrap();
        }

        while !self.session.can_finalize(&self.accum).unwrap() {
            // This can be checked if a timeout expired, to see which nodes have not responded yet.
            let unresponsive_parties =
                self.session.missing_messages(&self.accum).unwrap();
            assert!(!unresponsive_parties.is_empty());

            /*
            println!("{key_str}: waiting for a message");
            */

            let from = &message.body.0;
            let message = message.body.1.clone();
            // let (from, message) = rx.recv().await.unwrap();

            // Perform quick checks before proceeding with the verification.
            let preprocessed = self
                .session
                .preprocess_message(&mut self.accum, from, message)
                .unwrap();

            if let Some(preprocessed) = preprocessed {
                /*
                // In production usage, this will happen in a spawned task.
                println!("{key_str}: applying a message from {}", key_to_str(&from));
                */
                let result = self
                    .session
                    .process_message(preprocessed)
                    .unwrap();

                // This will happen in a host task.
                self.accum
                    .add_processed_message(result)
                    .unwrap()
                    .unwrap();
            }
        }

        /*
        match self
            .session
            .finalize_round(&mut OsRng, self.accum)
            .unwrap()
        {
            FinalizeOutcome::Success(res) => println!("{:#?}", res),
            FinalizeOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                self.session = new_session;
                self.cached_messages = new_cached_messages;
            }
        }
        */

        todo!();

        /*
        Ok(())
        */
    }

    fn proceed(&mut self) -> Result<Vec<Self::Outgoing>> {
        let mut outgoing = Vec::new();

        let destinations = self.session.message_destinations();
        for destination in destinations.iter() {
            // In production usage, this will happen in a spawned task
            // (since it can take some time to create a message),
            // and the artifact will be sent back to the host task
            // to be added to the accumulator.
            let (message, artifact) = self
                .session
                .make_message(&mut OsRng, destination)
                .unwrap();

            /*
            println!(
                "{key_str}: sending a message to {}",
                key_to_str(destination)
            );
            */

            // tx.send((key, *destination, message)).await.unwrap();

            // This will happen in a host task
            self.accum.add_artifact(artifact).unwrap();

            let body = (self.key, *destination, message);
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

            let msg = RoundMsg {
                body,
                sender: ((sender + 1) as u16).try_into()?,
                receiver: Some(((receiver + 1) as u16).try_into()?),
                round: (self.session.current_round().0 as u16)
                    .try_into()?,
            };

            outgoing.push(msg);
        }

        Ok(outgoing)
    }

    fn finish(mut self) -> Result<Self::Output> {
        /*
        match self
            .inner
            .finalize_round(&mut OsRng, self.accum)
            .unwrap()
        {
            FinalizeOutcome::Success(result) => Ok(result),
            _ => panic!(),
        }
        */

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
