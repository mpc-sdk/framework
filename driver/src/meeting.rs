use std::collections::HashSet;
use mpc_protocol::{UserId, MeetingState, MeetingId};
use mpc_client::{Client, ClientOptions, EventLoop, NetworkTransport};
use futures::{FutureExt, StreamExt};
use crate::{Result, MeetingOptions, ServerOptions, Event, Error};

/// Create a new meeting point.
pub async fn create(
    options: MeetingOptions,
    identifiers: Vec<UserId>,
    initiator: UserId,
) -> Result<MeetingId> {
    let num_ids = identifiers.len();
    let slots: HashSet<UserId> = identifiers.into_iter().collect();

    if slots.len() != num_ids {
        return Err(Error::MeetingIdentifiersNotUnique);
    }

    if slots.get(&initiator).is_none() {
        return Err(Error::MeetingInitiatorNotExist);
    }

    let ServerOptions { server_url, server_public_key, .. } = options.server;
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
                client.new_meeting(
                    initiator.clone(), slots.clone()).await?;
            }
            Event::MeetingCreated(meeting) => {
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
) -> Result<Vec<Vec<u8>>> {
    let ServerOptions { server_url, server_public_key, .. } = options.server;
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
                    client.join_meeting(
                        meeting_id.clone(), user_id.clone()).await?;
                }
            }
            Event::MeetingReady(meeting) => {
                let public_keys: Vec<Vec<u8>> =
                    meeting
                        .registered_participants
                        .into_iter()
                        .collect();
                return Ok(public_keys);
            }
            _ => {}
        }
    }
    unreachable!();
}
