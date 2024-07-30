//! Helper functions for the CGGMP protocol drivers.
use rand::rngs::OsRng;
use std::num::NonZeroU16;

use super::Result;
use synedrion::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    sessions::{PreprocessedMessage, RoundAccumulator, Session},
    ProtocolResult,
};

use crate::{key_to_str, Round, RoundInfo, RoundMsg};

use super::MessageOut;

pub fn round_info<Res>(
    session: &Session<Res, Signature, SigningKey, VerifyingKey>,
    accum: &RoundAccumulator<Signature, VerifyingKey>,
) -> Result<RoundInfo>
where
    Res: ProtocolResult + Send + 'static,
{
    let (round_number, is_echo) = session.current_round();
    let can_finalize = session.can_finalize(accum)?;
    Ok(RoundInfo {
        round_number,
        is_echo,
        can_finalize,
    })
}

pub fn proceed<Res>(
    session: &mut Session<Res, Signature, SigningKey, VerifyingKey>,
    accum: &mut RoundAccumulator<Signature, VerifyingKey>,
    verifiers: &[VerifyingKey],
    cached_messages: &mut Vec<
        PreprocessedMessage<Signature, VerifyingKey>,
    >,
    key: &VerifyingKey,
) -> Result<Vec<RoundMsg<MessageOut>>>
where
    Res: ProtocolResult + Send + 'static,
{
    let mut outgoing = Vec::new();

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
            session.make_message(&mut OsRng, destination)?;

        println!(
            "{key_str}: sending a message to {} (round = {})",
            key_to_str(destination),
            session.current_round().0,
        );

        // This will happen in a host task
        accum.add_artifact(artifact)?;

        let receiver =
            verifiers.iter().position(|i| i == destination).unwrap();

        let receiver: NonZeroU16 =
            ((receiver + 1) as u16).try_into()?;

        let round: NonZeroU16 =
            (session.current_round().0 as u16).try_into()?;

        outgoing.push(RoundMsg {
            body: message,
            sender: key.clone(),
            receiver,
            round,
        });
    }

    for preprocessed in cached_messages.drain(..) {
        // In production usage, this will happen in a spawned task.
        println!("{key_str}: applying a cached message");
        let mut rng = OsRng;
        let result =
            session.process_message(&mut rng, preprocessed).unwrap();

        // This will happen in a host task.
        accum.add_processed_message(result)??;
    }

    Ok(outgoing)
}

pub fn handle_incoming<Res>(
    session: &mut Session<Res, Signature, SigningKey, VerifyingKey>,
    accum: &mut RoundAccumulator<Signature, VerifyingKey>,
    message: RoundMsg<MessageOut>,
) -> Result<()>
where
    Res: ProtocolResult + Send + 'static,
{
    if !session.can_finalize(accum)? {
        let key_str = key_to_str(&session.verifier());
        tracing::info!(
            key = %key_str,
            current_round = session.current_round().0,
            message_round = message.round_number(),
            "handle_incoming",
        );

        // This can be checked if a timeout expired, to see
        // which nodes have not responded yet.
        let unresponsive_parties = session.missing_messages(accum)?;
        assert!(!unresponsive_parties.is_empty());

        let message_round_number = message.round_number();
        let (from, body) = message.into_body();

        // Perform quick checks before proceeding with the verification.
        let preprocessed =
            session.preprocess_message(accum, &from, body).unwrap();

        if let Some(preprocessed) = preprocessed {
            println!(
                "{key_str}: applying a message from {} (round {})",
                key_to_str(&from),
                message_round_number,
            );
            let mut rng = OsRng;
            let result = session
                .process_message(&mut rng, preprocessed)
                .unwrap();

            // This will happen in a host task.
            accum.add_processed_message(result)??;
        }
    }

    Ok(())
}
