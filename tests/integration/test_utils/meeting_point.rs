use anyhow::Result;
use futures::{select, FutureExt, StreamExt};

use mpc_client::{Event, NetworkTransport, Transport};
use super::new_client;

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<usize> {
    let mut completed: Vec<()> = Vec::new();

    // Create new clients
    let (client_i, event_loop_i, _) = new_client::<anyhow::Error>(
        server,
        server_public_key.clone(),
    )
    .await?;
    let (client_p, event_loop_p, _) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_transport: Transport = client_p.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_transport.connect().await?;

    // Meeting point limit is for a 2 of 2.
    let limit = 2;

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
                                client_i_transport.new_meeting(limit).await?;
                            }
                            Event::MeetingCreated(meeting) => {
                                // In the real world the initiator needs
                                // to share the meeting identifier with
                                // all the participants
                                client_p_transport.join_meeting(
                                    meeting.meeting_id).await?;
                            }
                            Event::MeetingReady(_) => {
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
                        if let Event::MeetingReady(_) = &event {
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
