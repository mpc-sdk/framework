use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use mpc_protocol::{hex, UserId};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use super::new_client;
use mpc_client::{Event, NetworkTransport, Transport};

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<usize> {
    let mut completed: Vec<()> = Vec::new();

    // Create new clients
    let (client_i, event_loop_i, init_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;
    let (client_p, event_loop_p, part_key) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    // Identifiers can be any arbitrary value, in the real world
    // this might be a nickname or email address
    let init_id: [u8; 32] =
        Sha256::digest("initiator".as_bytes()).try_into().unwrap();
    let part_id: [u8; 32] =
        Sha256::digest("participant".as_bytes()).try_into().unwrap();

    let init_id: UserId = init_id.into();
    let part_id: UserId = part_id.into();

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_transport: Transport = client_p.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_transport.connect().await?;

    // Expected public keys that should be broadcast
    // as the meeting ready event when the meeting point
    // limit has been reached
    let mut expected = vec![
        hex::encode(init_key.public_key()),
        hex::encode(part_key.public_key()),
    ];
    expected.sort();

    let mut s_i = event_loop_i.run();
    let mut s_p = event_loop_p.run();

    loop {
        if completed.len() == 2 {
            break;
        }

        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;

                        match event {
                            Event::ServerConnected { .. } => {

                                // Prepare enough slots for a 2 of 2
                                let mut slots = HashSet::new();
                                slots.insert(init_id.clone());
                                slots.insert(part_id.clone());

                                client_i_transport.new_meeting(
                                    init_id.clone(), slots, Value::Null).await?;
                            }
                            Event::MeetingCreated(meeting) => {
                                // In the real world the initiator needs
                                // to share the meeting/user identifiers with
                                // all the participants
                                client_p_transport.join_meeting(
                                    meeting.meeting_id, part_id.clone()).await?;
                            }
                            Event::MeetingReady(meeting) => {
                                let mut public_keys: Vec<String> =
                                    meeting
                                        .registered_participants
                                        .into_iter()
                                        .map(hex::encode)
                                        .collect();

                                public_keys.sort();
                                assert_eq!(expected, public_keys);

                                completed.push(());
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            },
            event = s_p.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Event::MeetingReady(meeting) = event {
                            let mut public_keys: Vec<String> =
                                meeting
                                    .registered_participants
                                    .into_iter()
                                    .map(hex::encode)
                                    .collect();

                            public_keys.sort();
                            assert_eq!(expected, public_keys);

                            completed.push(());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(completed.len())
}
