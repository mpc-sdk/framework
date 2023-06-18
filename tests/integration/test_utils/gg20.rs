use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::collections::HashMap;

use mpc_driver::{
    curv::elliptic::curves::secp256_k1::Secp256k1,
    gg20::KeyGenerator, gg_2020::state_machine::keygen::LocalKey,
    Parameters, SessionInitiator, SessionParticipant,
};

use mpc_relay_client::{NetworkTransport, Transport};
use mpc_relay_protocol::SessionState;

use super::new_client;

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    let mut sessions: Vec<SessionState> = Vec::new();

    // Create new clients
    let (client_i, event_loop_i, _) = new_client::<anyhow::Error>(
        server,
        server_public_key.clone(),
    )
    .await?;
    let (client_p_1, event_loop_p_1, participant_key_1) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let (client_p_2, event_loop_p_2, participant_key_2) =
        new_client::<anyhow::Error>(
            server,
            server_public_key.clone(),
        )
        .await?;

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_1_transport: Transport = client_p_1.into();
    let mut client_p_2_transport: Transport = client_p_2.into();

    let session_participants = vec![
        participant_key_1.public.clone(),
        participant_key_2.public.clone(),
    ];

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_1_transport.connect().await?;
    client_p_2_transport.connect().await?;

    let parameters = Parameters {
        parties: 3,
        threshold: 1, // Remember signing requires t + 1
    };

    let mut client_i_session = SessionInitiator::new(
        client_i_transport,
        session_participants,
    );
    let mut client_p_1_session =
        SessionParticipant::new(client_p_1_transport);

    let mut client_p_2_session =
        SessionParticipant::new(client_p_2_transport);

    let mut s_i = event_loop_i.run();
    let mut s_p_1 = event_loop_p_1.run();
    let mut s_p_2 = event_loop_p_2.run();

    // Prepare the sessions for each party
    loop {
        if sessions.len() == 3 {
            break;
        }

        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;

                        if let Some(session) =
                            client_i_session.create(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_p_1_session.join(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(session) =
                            client_p_2_session.join(event).await? {
                            sessions.push(session);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    log::info!("sessions ready, preparing for keygen");

    // Prepare for key generation
    let client_i_transport: Transport = client_i_session.into();
    let client_p_1_transport: Transport = client_p_1_session.into();
    let client_p_2_transport: Transport = client_p_2_session.into();

    let session_i = sessions.remove(0);
    let session_p_1 = sessions.remove(0);
    let session_p_2 = sessions.remove(0);

    println!(
        "session_i party_number {:#?}",
        session_i.party_number(client_i_transport.public_key())
    );
    println!(
        "session_p_1 party_number {:#?}",
        session_p_1.party_number(client_p_1_transport.public_key())
    );
    println!(
        "session_p_2 party_number {:#?}",
        session_p_2.party_number(client_p_2_transport.public_key())
    );

    let mut keygen_i = KeyGenerator::new(
        client_i_transport.clone(),
        parameters.clone(),
        session_i,
    )?;
    let mut keygen_p_1 = KeyGenerator::new(
        client_p_1_transport.clone(),
        parameters.clone(),
        session_p_1,
    )?;
    let mut keygen_p_2 = KeyGenerator::new(
        client_p_2_transport.clone(),
        parameters.clone(),
        session_p_2,
    )?;

    // Each party starts key generation protocol.
    keygen_i.execute().await?;
    keygen_p_1.execute().await?;
    keygen_p_2.execute().await?;

    let mut key_shares: HashMap<Vec<u8>, LocalKey<Secp256k1>> =
        HashMap::new();

    loop {
        if key_shares.len() == 3 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_share) =
                            keygen_i.handle_event(event).await? {
                            key_shares.insert(
                                client_i_transport.public_key().to_vec(),
                                key_share);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_1.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_share) =
                            keygen_p_1.handle_event(event).await? {
                            key_shares.insert(
                                client_p_1_transport.public_key().to_vec(),
                                key_share);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(key_share) =
                            keygen_p_2.handle_event(event).await? {
                            key_shares.insert(
                                client_p_2_transport.public_key().to_vec(),
                                key_share);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    let local_key_i =
        key_shares.remove(client_i_transport.public_key()).unwrap();
    let local_key_p_1 = key_shares
        .remove(client_p_1_transport.public_key())
        .unwrap();
    let local_key_p_2 = key_shares
        .remove(client_p_2_transport.public_key())
        .unwrap();

    println!("local key i index {}", local_key_i.i);
    println!("local key p_1 index {}", local_key_p_1.i);
    println!("local key p_2 index {}", local_key_p_2.i);

    Ok(())
}
