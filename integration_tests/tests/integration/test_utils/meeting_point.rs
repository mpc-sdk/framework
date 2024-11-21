use anyhow::Result;
use futures::StreamExt;
use polysig_protocol::{MeetingState, UserId};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

use super::new_meeting_client;
use polysig_client::{NetworkTransport, Transport};
use polysig_protocol::Event;

pub async fn run(
    server: &str,
    num_participants: usize,
) -> Result<usize> {
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

    let meeting: Arc<Mutex<Option<MeetingState>>> =
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
        let value = Value::Null;

        transport.new_meeting(init_id.clone(), slots, value).await?;

        while let Some(event) = stream.next().await {
            let event = event?;
            match event {
                Event::MeetingCreated(meeting) => {
                    // In the real world the initiator needs
                    // to share the meeting/user identifiers with
                    // all the participants
                    let mut writer = state.lock().await;
                    *writer = Some(meeting);
                }
                Event::MeetingReady(_) => {
                    break;
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    tasks.push(creator);

    for ((client, event_loop), user_id) in
        join_clients.into_iter().zip(join_ids.into_iter())
    {
        let state = meeting.clone();
        tasks.push(tokio::task::spawn(async move {
            let mut stream = event_loop.run();
            let mut transport: Transport = client.into();
            'main: loop {
                let lock = state.lock().await;
                if let Some(meeting) = &*lock {
                    transport
                        .join_meeting(meeting.meeting_id, user_id)
                        .await?;

                    while let Some(event) = stream.next().await {
                        let event = event?;
                        match event {
                            Event::MeetingReady(_) => {
                                break 'main;
                            }
                            _ => {}
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(5))
                        .await;
                }
            }
            Ok::<_, anyhow::Error>(())
        }));
    }

    let results = futures::future::try_join_all(tasks).await?;
    let num_results = results.len();
    for result in results {
        result?;
    }
    Ok(num_results)
}
