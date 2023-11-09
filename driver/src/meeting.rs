//! Create and join meeting points so session participants
//! can exchange public keys.
//!
//! The meeting identifier is the shared secret that participants
//! can use to exchange public keys so should only be given to parties
//! that should be included in a session.
use crate::{Error, Event, MeetingOptions, Result, ServerOptions};
use futures::StreamExt;
use mpc_client::{Client, ClientOptions, NetworkTransport};
use mpc_protocol::{MeetingId, UserId};
use serde_json::Value;
use std::collections::HashSet;

/// Create a new meeting point.
pub async fn create(
    options: MeetingOptions,
    identifiers: Vec<UserId>,
    initiator: UserId,
    data: Value,
) -> Result<MeetingId> {
    let num_ids = identifiers.len();
    let slots: HashSet<UserId> = identifiers.into_iter().collect();

    if slots.len() != num_ids {
        return Err(Error::MeetingIdentifiersNotUnique);
    }

    if slots.get(&initiator).is_none() {
        return Err(Error::MeetingInitiatorNotExist);
    }

    let ServerOptions {
        server_url,
        server_public_key,
        ..
    } = options.server;
    let options = ClientOptions {
        keypair: options.keypair,
        server_public_key,
        pattern: None,
    };
    let url = options.url(&server_url);
    let (mut client, event_loop) = Client::new(&url, options).await?;

    client.connect().await?;

    let mut stream = event_loop.run();
    while let Some(event) = stream.next().await {
        let event = event?;
        match event {
            Event::ServerConnected { .. } => {
                client
                    .new_meeting(
                        initiator.clone(),
                        slots.clone(),
                        data.clone(),
                    )
                    .await?;
            }
            Event::MeetingCreated(meeting) => {
                let _ = client.close().await;
                return Ok(meeting.meeting_id);
            }
            _ => {}
        }
    }
    unreachable!();
}

/// Join a meeting point.
///
/// When all participants have joined the meeting point the public
/// keys of all participants are returned.
///
/// When  the user identifier is not given then the user is
/// the creator of the meeting point who has already been
/// registered as a participant when creating the meeting.
pub async fn join(
    options: MeetingOptions,
    meeting_id: MeetingId,
    user_id: Option<UserId>,
) -> Result<(Vec<Vec<u8>>, Value)> {
    let ServerOptions {
        server_url,
        server_public_key,
        ..
    } = options.server;
    let options = ClientOptions {
        keypair: options.keypair,
        server_public_key,
        pattern: None,
    };
    let url = options.url(&server_url);
    let (mut client, event_loop) = Client::new(&url, options).await?;

    client.connect().await?;

    let mut stream = event_loop.run();
    while let Some(event) = stream.next().await {
        let event = event?;
        match event {
            Event::ServerConnected { .. } => {
                if let Some(user_id) = &user_id {
                    client
                        .join_meeting(meeting_id, user_id.clone())
                        .await?;
                }
            }
            Event::MeetingReady(meeting) => {
                let _ = client.close().await;
                let public_keys: Vec<Vec<u8>> = meeting
                    .registered_participants
                    .into_iter()
                    .collect();
                return Ok((public_keys, meeting.data));
            }
            _ => {}
        }
    }
    unreachable!();
}
