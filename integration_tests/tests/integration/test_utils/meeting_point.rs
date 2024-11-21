use anyhow::Result;
use futures::StreamExt;
use polysig_protocol::{
    MeetingClientMessage, MeetingData, MeetingId, UserId,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

use super::new_meeting_client;
use polysig_client::{NetworkTransport, Transport};
use polysig_protocol::Event;

pub async fn run(server: &str, num_participants: u8) -> Result<u8> {
    // Create new clients
    let (client, event_loop) =
        new_meeting_client::<anyhow::Error>(server).await?;

    // Identifiers can be any arbitrary value, in the real world
    // this might be the hash of a nickname or email address
    let init_id: [u8; 32] =
        Sha256::digest("initiator".as_bytes()).try_into().unwrap();
    let init_id: UserId = init_id.into();

    let mut transport: Transport = client.into();

    let mut join_clients = Vec::new();
    for _ in 1..num_participants {
        join_clients
            .push(new_meeting_client::<anyhow::Error>(server).await?);
    }

    let mut join_ids: HashSet<UserId> = HashSet::new();
    for i in 1..num_participants {
        let part_id =
            Sha256::digest(format!("participant_{}", i).as_bytes());
        let part_id: [u8; 32] = part_id.try_into().unwrap();
        join_ids.insert(part_id.try_into()?);
    }

    let mut stream = event_loop.run();

    let mut tasks = Vec::new();

    let meeting: Arc<Mutex<Option<MeetingId>>> =
        Arc::new(Mutex::new(None));

    // Prepare enough slots for all participants
    let mut slots = HashSet::new();
    slots.insert(init_id.clone());
    for id in &join_ids {
        slots.insert(id.clone());
    }

    let state = meeting.clone();
    let creator = tokio::task::spawn(async move {
        // In the real world this would be the public keys
        // for each participant
        let value = MeetingData {
            public_key: vec![0],
            verifying_key: vec![0],
            associated_data: None,
        };

        transport.new_meeting(init_id.clone(), slots, value).await?;

        while let Some(event) = stream.next().await {
            let event = event?;
            match event {
                Event::Meeting(
                    MeetingClientMessage::RoomCreated {
                        meeting_id,
                        ..
                    },
                ) => {
                    let mut writer = state.lock().await;
                    *writer = Some(meeting_id);
                }
                Event::Meeting(MeetingClientMessage::RoomReady {
                    participants,
                }) => {
                    transport.close().await?;
                    return Ok::<_, anyhow::Error>(participants);
                }
                _ => {}
            }
        }
        unreachable!();
    });
    tasks.push(creator);

    for (index, ((client, event_loop), user_id)) in join_clients
        .into_iter()
        .zip(join_ids.into_iter())
        .enumerate()
    {
        let state = meeting.clone();
        tasks.push(tokio::task::spawn(async move {
            let mut stream = event_loop.run();
            let mut transport: Transport = client.into();
            loop {
                let meeting_id = {
                    let lock = state.lock().await;
                    lock.clone()
                };
                if let Some(meeting_id) = meeting_id {
                    let value = MeetingData {
                        public_key: vec![index as u8 + 1],
                        verifying_key: vec![index as u8 + 1],
                        associated_data: None,
                    };
                    transport
                        .join_meeting(meeting_id, user_id, value)
                        .await?;

                    while let Some(event) = stream.next().await {
                        let event = event?;
                        match event {
                            Event::Meeting(
                                MeetingClientMessage::RoomReady {
                                    participants,
                                },
                            ) => {
                                transport.close().await?;
                                return Ok::<_, anyhow::Error>(
                                    participants,
                                );
                            }
                            _ => {}
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(5))
                        .await;
                }
            }
        }));
    }

    let mut parties = Vec::new();
    let results = futures::future::try_join_all(tasks).await?;
    let num_results = results.len();
    for result in results {
        let participants = result?;
        parties.push(participants);
    }

    let all_equal = parties.windows(2).all(|w| w[0] == w[1]);
    assert!(all_equal);

    Ok(num_results as u8)
}
