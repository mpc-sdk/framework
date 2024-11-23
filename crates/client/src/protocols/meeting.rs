//! Create and join meeting points so session participants
//! can exchange public keys.
//!
//! The meeting identifier is the shared secret that participants
//! can use to exchange public keys so should only be given to parties
//! that should be included in a session.
use crate::{Client, ClientOptions, Error, NetworkTransport, Result};
use futures::StreamExt;
use polysig_protocol::{
    Event, PublicKeys, MeetingId, MeetingResponse, UserId,
};
use std::collections::HashSet;

/// Create a new meeting room.
pub async fn create(
    server_url: &str,
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

    let options = ClientOptions::default();
    let (mut client, event_loop) =
        Client::new(server_url, options).await?;

    client.new_meeting(initiator, slots).await?;

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

/// Join a meeting room.
///
/// When all participants have joined the meeting point the public
/// keys of all participants are returned.
pub async fn join(
    server_url: &str,
    meeting_id: MeetingId,
    user_id: UserId,
    data: PublicKeys,
) -> Result<Vec<(UserId, PublicKeys)>> {
    let options = ClientOptions::default();
    let (mut client, event_loop) =
        Client::new(server_url, options).await?;

    client.join_meeting(meeting_id, user_id, data).await?;

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
