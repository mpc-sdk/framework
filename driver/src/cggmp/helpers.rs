//! Key generation for CGGMP.
use rand::rngs::OsRng;
use std::num::NonZeroU16;

use super::Result;
use synedrion::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    sessions::{PreprocessedMessage, RoundAccumulator, Session},
    MappedResult, ProtocolResult,
};

use crate::{key_to_str, RoundMsg};

use super::MessageOut;

pub fn proceed<Res>(
    session: &mut Session<Res, Signature, SigningKey, VerifyingKey>,
    accum: &mut RoundAccumulator<Signature>,
    verifiers: &[VerifyingKey],
    cached_messages: &mut Vec<PreprocessedMessage<Signature>>,
    key: &VerifyingKey,
) -> Result<Vec<RoundMsg<MessageOut>>>
where
    Res: MappedResult<VerifyingKey>,
    Res: ProtocolResult,
{
    let mut outgoing = Vec::new();

    // let session = self.session.as_mut().unwrap();
    // let accum = self.accum.as_mut().unwrap();

    let destinations = session.message_destinations();
    let key_str = key_to_str(&session.verifier());

    println!(
        "{key_str}: *** starting round {:?} ***",
        session.current_round()
    );

    for destination in destinations.iter() {
        // In production usage, this will happen in a spawned task
        // (since it can take some time to create a message),
        // and the artifact will be sent back to the host task
        // to be added to the accumulator.
        let (message, artifact) =
            session.make_message(&mut OsRng, destination).unwrap();

        println!(
            "{key_str}: sending a message to {}",
            key_to_str(destination)
        );

        // This will happen in a host task
        accum.add_artifact(artifact).unwrap();

        let sender = verifiers.iter().position(|i| i == key).unwrap();

        let receiver =
            verifiers.iter().position(|i| i == destination).unwrap();

        let sender: NonZeroU16 = ((sender + 1) as u16).try_into()?;
        let receiver: NonZeroU16 =
            ((receiver + 1) as u16).try_into()?;
        let round: NonZeroU16 =
            (session.current_round().0 as u16).try_into()?;

        outgoing.push(RoundMsg {
            body: (key.clone(), message),
            sender: key.clone(),
            receiver,
            round,
        });
    }

    for preprocessed in cached_messages.drain(..) {
        // In production usage, this will happen in a spawned task.
        println!("{key_str}: applying a cached message");
        let result = session.process_message(preprocessed).unwrap();

        // This will happen in a host task.
        accum.add_processed_message(result).unwrap().unwrap();
    }

    Ok(outgoing)
}

pub fn handle_incoming<Res>(
    session: &mut Session<Res, Signature, SigningKey, VerifyingKey>,
    accum: &mut RoundAccumulator<Signature>,
    message: RoundMsg<MessageOut>,
) -> Result<()>
where
    Res: MappedResult<VerifyingKey>,
    Res: ProtocolResult,
{
    if !session.can_finalize(accum).unwrap() {
        let key_str = key_to_str(&session.verifier());
        tracing::info!(
            "handle incoming (round = {})",
            session.current_round().0,
        );

        // This can be checked if a timeout expired, to see which nodes have not responded yet.
        let unresponsive_parties =
            session.missing_messages(accum).unwrap();
        assert!(!unresponsive_parties.is_empty());

        /*
        println!("{key_str}: waiting for a message");
        */

        let from = &message.body.0;
        let message = message.body.1.clone();
        // let (from, message) = rx.recv().await.unwrap();

        // Perform quick checks before proceeding with the verification.
        let preprocessed =
            session.preprocess_message(accum, from, message).unwrap();

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
