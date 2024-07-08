//! Driver for the CGGMP protocol.
use futures::StreamExt;
use mpc_client::{Event, EventStream};
use mpc_protocol::{SessionId as ProtocolSessionId, SessionState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use synedrion::{
    ecdsa::{self, SigningKey, VerifyingKey},
    KeyResharingInputs, KeyShare as SynedrionKeyShare, MessageBundle,
    NewHolder, OldHolder, PrehashedMessage, RecoverableSignature,
    SchemeParams, SessionId, ThresholdKeyShare,
};

mod aux_gen;
mod error;
mod helpers;
mod key_gen;
mod key_init;
mod key_refresh;
mod key_resharing;
mod sign;

pub use aux_gen::AuxGenDriver;
pub use error::Error;
pub use key_gen::KeyGenDriver;
pub use key_init::KeyInitDriver;
pub use key_refresh::KeyRefreshDriver;
pub use key_resharing::KeyResharingDriver;
pub use sign::SignatureDriver;

type MessageOut = MessageBundle<ecdsa::Signature>;

/// Message sent by key init participants to
/// notify clients that are not participating
/// that their key init phase is completed.
#[derive(Serialize, Deserialize)]
pub struct KeyInitAck {
    /// Index of the party.
    pub party_index: usize,
    /// Verifying key from the generated threshold key share.
    pub key_share_verifying_key: VerifyingKey,
}

/// Key share.
pub type KeyShare<P> = SynedrionKeyShare<P, VerifyingKey>;

/// Result type for the CGGMP protocol.
pub type Result<T> = std::result::Result<T, Error>;

use mpc_client::{NetworkTransport, Transport};

use crate::{
    new_client, wait_for_close, wait_for_driver, wait_for_session,
    wait_for_session_finish, SessionHandler, SessionInitiator,
    SessionOptions, SessionParticipant,
};

/// Run DKG for the CGGMP protocol.
pub async fn keygen<P: SchemeParams + 'static>(
    options: SessionOptions,
    participants: Option<Vec<Vec<u8>>>,
    session_id: SessionId,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
) -> crate::Result<SynedrionKeyShare<P, VerifyingKey>> {
    let is_initiator = participants.is_some();

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if let Some(participants) = participants {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    // Wait for key generation
    let keygen = KeyGenDriver::<P>::new(
        transport, session, session_id, signer, verifiers,
    )?;

    let (mut transport, key_share) =
        wait_for_driver(&mut stream, keygen).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(key_share.0)
}

/// Run threshold DKG for the CGGMP protocol.
pub async fn threshold_keygen<P: SchemeParams + 'static>(
    options: SessionOptions,
    public_key: Vec<u8>,
    participants: Vec<Vec<u8>>,
    is_initiator: bool,
    session_id: SessionId,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
    // ) -> crate::Result<ThresholdKeyShare<P, VerifyingKey>> {
) -> crate::Result<()> {
    let party_index = verifiers
        .iter()
        .position(|v| v == signer.verifying_key())
        .ok_or(Error::NotVerifyingParty)?;

    let n = options.parameters.parties as usize;
    let t = options.parameters.threshold as usize;

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if is_initiator {
        let mut other_participants = participants.clone();
        other_participants.retain(|p| p != &public_key);
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            other_participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    let (transport, stream, t_key_share, acks) = make_dkg_init::<P>(
        t,
        party_index,
        transport,
        stream,
        participants.as_slice(),
        protocol_session_id,
        session.clone(),
        session_id,
        &signer,
        &verifiers,
    )
    .await?;

    println!("START DKG RESHARE {}", party_index);

    let (mut transport, mut stream, t_key_share) =
        make_dkg_reshare::<P>(
            t,
            t_key_share,
            acks,
            transport,
            stream,
            session,
            session_id,
            signer,
            verifiers,
        )
        .await?;

    println!("DKG RESHARE COMPLETED: {}", party_index);

    /*
    // WARN: this is a temporary hack to ensure the streams
    // WARN: are not dropped immediately which would prevent
    // WARN: the key init other participants from receiving the
    // WARN: ack
    while let Some(event) = stream.next().await {
        let event = event?;
    }
    */

    /*
    // Wait for the session to become active
    let client_session = if let Some(participants) = participants {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };

    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    // Wait for key generation
    let keygen = KeyInitDriver::<P>::new(
        transport, session, session_id, signer, verifiers,
    )?;

    let (mut transport, key_share) =
        wait_for_driver(&mut stream, keygen).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }

    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(ThresholdKeyShare::from_key_share(&key_share))
    */

    /*
    // Close the session and socket
    if is_initiator {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }

    transport.close().await?;
    wait_for_close(&mut stream).await?;
    */

    Ok(())
}

/// Make initialize key share for threshold DKG.
async fn make_dkg_init<P: SchemeParams + 'static>(
    t: usize,
    party_index: usize,
    transport: Transport,
    mut stream: EventStream,
    participants: &[Vec<u8>],
    protocol_session_id: ProtocolSessionId,
    session: SessionState,
    session_id: SessionId,
    signer: &SigningKey,
    verifiers: &[VerifyingKey],
) -> crate::Result<(
    Transport,
    EventStream,
    Option<ThresholdKeyShare<P, VerifyingKey>>,
    Vec<KeyInitAck>,
)> {
    let init_verifiers =
        verifiers.iter().take(t).cloned().collect::<Vec<_>>();

    if party_index < t {
        // Wait for key init generation
        let key_init = KeyInitDriver::<P>::new(
            transport,
            session,
            session_id,
            signer.to_owned(),
            init_verifiers,
        )?;

        let (mut transport, key_share) =
            wait_for_driver(&mut stream, key_init).await?;

        let ack = KeyInitAck {
            party_index,
            key_share_verifying_key: key_share
                .verifying_key()
                .clone(),
        };

        // Notify participants not involved in key init
        // that we are done
        let other_participants = &participants[t..];
        for other_public_key in other_participants {
            transport
                .send_json(
                    other_public_key,
                    &ack,
                    Some(protocol_session_id),
                )
                .await?;
        }

        let mut acks = vec![ack];

        /*
        while let Some(event) = stream.next().await {
            let event = event?;
            if let Event::JsonMessage {
                message,
                session_id,
                ..
            } = event
            {
                if session_id.as_ref() == Some(&protocol_session_id) {
                    if let Ok(ack) =
                        message.deserialize::<KeyInitAck>()
                    {
                        acks.push(ack);
                        if acks.len() == t {
                            break;
                        }
                    }
                }
            }
        }
        */

        let t_key_share =
            ThresholdKeyShare::from_key_share(&key_share);

        Ok((transport, stream, Some(t_key_share), acks))
    } else {
        // If we are not participating in key init then wait
        // so we know when to proceed to the key resharing phase
        let mut acks = Vec::new();
        while let Some(event) = stream.next().await {
            let event = event?;
            if let Event::JsonMessage {
                message,
                session_id,
                ..
            } = event
            {
                if session_id.as_ref() == Some(&protocol_session_id) {
                    if let Ok(ack) =
                        message.deserialize::<KeyInitAck>()
                    {
                        acks.push(ack);
                        if acks.len() == t {
                            break;
                        }
                    }
                }
            }
        }
        Ok((transport, stream, None, acks))
    }
}

/// Drive the key resharing phase of threshold DKG.
async fn make_dkg_reshare<P: SchemeParams + 'static>(
    t: usize,
    t_key_share: Option<ThresholdKeyShare<P, VerifyingKey>>,
    acks: Vec<KeyInitAck>,
    transport: Transport,
    mut stream: EventStream,
    session: SessionState,
    session_id: SessionId,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
) -> Result<(
    Transport,
    EventStream,
    ThresholdKeyShare<P, VerifyingKey>,
)> {
    let old_holders =
        BTreeSet::from_iter(verifiers.iter().cloned().take(t));

    let inputs = if let Some(t_key_share) = t_key_share {
        let new_holder = NewHolder {
            verifying_key: t_key_share.verifying_key().clone(),
            old_threshold: t,
            old_holders,
        };

        KeyResharingInputs {
            old_holder: Some(OldHolder {
                key_share: t_key_share.clone(),
            }),
            new_holder: Some(new_holder.clone()),
            new_holders: verifiers
                .clone()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            new_threshold: t,
        }
    } else {
        let ack = acks.iter().find(|a| a.party_index == 0).unwrap();
        let new_holder = NewHolder {
            verifying_key: ack.key_share_verifying_key.clone(),
            old_threshold: t,
            old_holders,
        };

        KeyResharingInputs {
            old_holder: None,
            new_holder: Some(new_holder.clone()),
            new_holders: verifiers
                .clone()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            new_threshold: t,
        }
    };

    let driver = KeyResharingDriver::<P>::new(
        transport,
        session,
        session_id,
        signer,
        verifiers.clone(),
        inputs,
    )?;

    let (transport, key_share) =
        wait_for_driver(&mut stream, driver).await?;

    Ok((transport, stream, key_share))
}

/// Sign a message using the CGGMP protocol.
pub async fn sign<P: SchemeParams + 'static>(
    options: SessionOptions,
    participants: Option<Vec<Vec<u8>>>,
    session_id: SessionId,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
    key_share: &SynedrionKeyShare<P, VerifyingKey>,
    prehashed_message: &PrehashedMessage,
) -> crate::Result<RecoverableSignature> {
    let is_initiator = participants.is_some();

    // Create the client
    let (client, event_loop) = new_client(options).await?;

    let mut transport: Transport = client.into();

    // Handshake with the server
    transport.connect().await?;

    // Start the event stream
    let mut stream = event_loop.run();

    // Wait for the session to become active
    let client_session = if let Some(participants) = participants {
        SessionHandler::Initiator(SessionInitiator::new(
            transport,
            participants,
        ))
    } else {
        SessionHandler::Participant(SessionParticipant::new(
            transport,
        ))
    };
    let (transport, session) =
        wait_for_session(&mut stream, client_session).await?;

    let protocol_session_id = session.session_id;

    /*
    let selected_signers =
        vec![signers[0].clone(), signers[2].clone()];
    let selected_parties = vec![verifiers[0], verifiers[2]];
    let selected_parties_set =
        BTreeSet::from([verifiers[0], verifiers[2]]);
    let selected_key_shares = vec![
        new_t_key_shares[0].to_key_share(&selected_parties_set),
        new_t_key_shares[2].to_key_share(&selected_parties_set),
    ];
    let selected_aux_infos =
        vec![aux_infos[0].clone(), aux_infos[2].clone()];
    */

    // Wait for aux gen protocol to complete
    let driver = AuxGenDriver::<P>::new(
        transport,
        session.clone(),
        session_id,
        signer.clone(),
        verifiers.clone(),
    )?;
    let (transport, aux_info) =
        wait_for_driver(&mut stream, driver).await?;

    // Wait for message to be signed
    let driver = SignatureDriver::<P>::new(
        transport,
        // parameters,
        session,
        session_id,
        signer,
        verifiers,
        key_share,
        &aux_info,
        prehashed_message,
    )?;
    let (mut transport, signature) =
        wait_for_driver(&mut stream, driver).await?;

    // Close the session and socket
    if is_initiator {
        transport.close_session(protocol_session_id).await?;
        wait_for_session_finish(&mut stream, protocol_session_id)
            .await?;
    }
    transport.close().await?;
    wait_for_close(&mut stream).await?;

    Ok(signature)
}
