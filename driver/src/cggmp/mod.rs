//! Driver for the CGGMP protocol.
use synedrion::{
    ecdsa::{self, SigningKey, VerifyingKey},
    KeyShare as SynedrionKeyShare, MessageBundle, PrehashedMessage,
    RecoverableSignature, SchemeParams, SessionId,
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

/// Run distributed key generation for the CGGMP protocol.
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
