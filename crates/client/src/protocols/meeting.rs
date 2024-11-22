//! Create and join meeting points so session participants
//! can exchange public keys.
//!
//! The meeting identifier is the shared secret that participants
//! can use to exchange public keys so should only be given to parties
//! that should be included in a session.
use crate::{
    Client, ClientOptions, Error, NetworkTransport, Result,
    ServerOptions,
};
use futures::StreamExt;
use polysig_protocol::{
    Event, MeetingData, MeetingId, MeetingResponse, UserId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Create a new meeting point.
pub async fn create(
    options: ServerOptions,
    identifiers: Vec<UserId>,
    initiator: UserId,
    data: MeetingData,
) -> Result<MeetingId> {
    let num_ids = identifiers.len();
    let slots: HashSet<UserId> = identifiers.into_iter().collect();

    if slots.len() != num_ids {
        return Err(Error::MeetingIdentifiersNotUnique);
    }

    if slots.get(&initiator).is_none() {
        return Err(Error::MeetingInitiatorNotExist);
    }

    let ServerOptions { server_url, .. } = options;
    let options = ClientOptions::default();
    let url = options.url(&server_url);
    let (mut client, event_loop) = Client::new(&url, options).await?;

    client.new_meeting(initiator.clone(), slots, data).await?;

    let mut stream = event_loop.run();
    while let Some(event) = stream.next().await {
        let event = event?;
        match event {
            Event::Meeting(MeetingResponse::RoomCreated {
                meeting_id,
                ..
            }) => {
                let _ = client.close().await;
                return Ok(meeting_id);
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
/// When the user identifier is not given then the user is
/// the creator of the meeting point who has already been
/// registered as a participant when creating the meeting.
pub async fn join(
    options: ServerOptions,
    meeting_id: MeetingId,
    user_id: Option<UserId>,
    data: MeetingData,
) -> Result<Vec<(UserId, MeetingData)>> {
    let ServerOptions { server_url, .. } = options;
    let options = ClientOptions::default();
    let url = options.url(&server_url);
    let (mut client, event_loop) = Client::new(&url, options).await?;

    if let Some(user_id) = &user_id {
        client.join_meeting(meeting_id, *user_id, data).await?;
    }

    let mut stream = event_loop.run();
    while let Some(event) = stream.next().await {
        let event = event?;
        match event {
            Event::Meeting(MeetingResponse::RoomReady {
                participants,
            }) => {
                let _ = client.close().await;
                return Ok(participants);
            }
            _ => {}
        }
    }
    unreachable!();
}
