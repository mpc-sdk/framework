use anyhow::Result;
use futures::{select, FutureExt, StreamExt};
use std::collections::HashMap;

use mpc_driver::{
    curv::elliptic::curves::secp256_k1::Secp256k1,
    gg20::{
        KeyGenerator, ParticipantGenerator, PreSignGenerator,
        Signature, SignatureGenerator,
    },
    gg_2020::state_machine::{
        keygen::LocalKey, sign::CompletedOfflineStage,
    },
    Parameters, SessionInitiator, SessionParticipant,
};

use mpc_relay_client::{NetworkTransport, Transport};
use mpc_relay_protocol::{Keypair, PartyNumber, SessionState};

use sha3::{Digest, Keccak256};

use super::{new_client, new_client_with_keypair};

pub async fn run(
    server: &str,
    server_public_key: Vec<u8>,
) -> Result<()> {
    // 2 of 3
    let parameters = Parameters {
        parties: 3,
        threshold: 1, // Remember signing requires t + 1
    };

    let (key_shares, keypairs) = gg20_keygen(
        server,
        server_public_key.clone(),
        parameters.clone(),
    )
    .await?;

    let sign_keypairs = keypairs.iter().map(|k| k.clone()).collect();

    let pre_signatures = gg20_sign_offline(
        server,
        server_public_key.clone(),
        parameters.clone(),
        sign_keypairs,
        key_shares,
    )
    .await?;

    let message = "this is the message that is sent out";
    let message: [u8; 32] = Keccak256::digest(message.as_bytes())
        .as_slice()
        .try_into()?;

    let signatures = gg20_sign_online(
        server,
        server_public_key.clone(),
        parameters.clone(),
        keypairs,
        pre_signatures,
        message,
    )
    .await?;

    assert_eq!(2, signatures.len());

    Ok(())
}

/// Create a new session and then perform
/// distributed key generation.
async fn gg20_keygen(
    server: &str,
    server_public_key: Vec<u8>,
    parameters: Parameters,
) -> Result<(HashMap<Vec<u8>, LocalKey<Secp256k1>>, Vec<Keypair>)> {
    let mut sessions: Vec<SessionState> = Vec::new();

    // Create new clients
    let (client_i, event_loop_i, initiator_key) =
        new_client::<anyhow::Error>(
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

    let keypairs = vec![
        initiator_key.clone(),
        participant_key_1.clone(),
        participant_key_2.clone(),
    ];

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_1_transport: Transport = client_p_1.into();
    let mut client_p_2_transport: Transport = client_p_2.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_1_transport.connect().await?;
    client_p_2_transport.connect().await?;

    // Event loop streams
    let mut s_i = event_loop_i.run();
    let mut s_p_1 = event_loop_p_1.run();
    let mut s_p_2 = event_loop_p_2.run();

    let session_participants = vec![
        participant_key_1.public_key().to_vec(),
        participant_key_2.public_key().to_vec(),
    ];

    let mut client_i_session = SessionInitiator::new(
        client_i_transport,
        session_participants,
    );
    let mut client_p_1_session =
        SessionParticipant::new(client_p_1_transport);

    let mut client_p_2_session =
        SessionParticipant::new(client_p_2_transport);

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

    // Prepare for key generation
    let client_i_transport: Transport = client_i_session.into();
    let client_p_1_transport: Transport = client_p_1_session.into();
    let client_p_2_transport: Transport = client_p_2_session.into();

    let session_i = sessions.remove(0);
    let session_p_1 = sessions.remove(0);
    let session_p_2 = sessions.remove(0);

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

    Ok((key_shares, keypairs))
}

/// Create a new session and then perform
/// pre-signature generation.
async fn gg20_sign_offline(
    server: &str,
    server_public_key: Vec<u8>,
    parameters: Parameters,
    mut keypairs: Vec<Keypair>,
    mut key_shares: HashMap<Vec<u8>, LocalKey<Secp256k1>>,
) -> Result<HashMap<Vec<u8>, CompletedOfflineStage>> {
    let initiator_key = keypairs.remove(0);
    let participant_key_2 = keypairs.pop().unwrap();

    let sign_participants =
        vec![participant_key_2.public_key().to_vec()];

    // Create new clients for signing
    let (client_i, event_loop_i) =
        new_client_with_keypair::<anyhow::Error>(
            server,
            server_public_key.clone(),
            initiator_key,
        )
        .await?;
    let (client_p_2, event_loop_p_2) =
        new_client_with_keypair::<anyhow::Error>(
            server,
            server_public_key.clone(),
            participant_key_2,
        )
        .await?;

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_2_transport: Transport = client_p_2.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_2_transport.connect().await?;

    let mut s_i = event_loop_i.run();
    let mut s_p_2 = event_loop_p_2.run();

    let local_key_i =
        key_shares.remove(client_i_transport.public_key()).unwrap();
    let local_key_p_2 = key_shares
        .remove(client_p_2_transport.public_key())
        .unwrap();

    let mut sessions: Vec<SessionState> = Vec::new();

    let mut client_i_session =
        SessionInitiator::new(client_i_transport, sign_participants);
    let mut client_p_2_session =
        SessionParticipant::new(client_p_2_transport);

    // Prepare the sessions for each party
    loop {
        if sessions.len() == 2 {
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

    // Prepare for pre-signature generation
    let client_i_transport: Transport = client_i_session.into();
    let client_p_2_transport: Transport = client_p_2_session.into();

    let session_i = sessions.remove(0);
    let session_p_2 = sessions.remove(0);

    let mut part_i = ParticipantGenerator::new(
        client_i_transport.clone(),
        parameters.clone(),
        session_i.clone(),
        PartyNumber::new(local_key_i.i).unwrap(),
    )?;

    let mut part_p_2 = ParticipantGenerator::new(
        client_p_2_transport.clone(),
        parameters.clone(),
        session_p_2.clone(),
        PartyNumber::new(local_key_p_2.i).unwrap(),
    )?;

    // Get participant party numbers assigned when the local
    // keys were generated.
    part_i.execute().await?;
    part_p_2.execute().await?;

    let mut participant_lists: HashMap<Vec<u8>, Vec<u16>> =
        HashMap::new();
    loop {
        if participant_lists.len() == 2 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(list) =
                            part_i.handle_event(event).await? {
                            participant_lists.insert(
                                client_i_transport.public_key().to_vec(),
                                list);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(list) =
                            part_p_2.handle_event(event).await? {
                            participant_lists.insert(
                                client_p_2_transport.public_key().to_vec(),
                                list);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    let participants_i = participant_lists
        .remove(client_i_transport.public_key())
        .unwrap();
    let participants_p_2 = participant_lists
        .remove(client_p_2_transport.public_key())
        .unwrap();

    let mut presign_i = PreSignGenerator::new(
        client_i_transport.clone(),
        parameters.clone(),
        session_i,
        local_key_i,
        participants_i,
    )?;
    let mut presign_p_2 = PreSignGenerator::new(
        client_p_2_transport.clone(),
        parameters.clone(),
        session_p_2,
        local_key_p_2,
        participants_p_2,
    )?;

    // Each party starts pre-signature generation.
    presign_i.execute().await?;
    presign_p_2.execute().await?;

    let mut pre_signatures: HashMap<Vec<u8>, CompletedOfflineStage> =
        HashMap::new();

    loop {
        if pre_signatures.len() == 2 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(pre_signature) =
                            presign_i.handle_event(event).await? {
                            pre_signatures.insert(
                                client_i_transport.public_key().to_vec(),
                                pre_signature);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(pre_signature) =
                            presign_p_2.handle_event(event).await? {
                            pre_signatures.insert(
                                client_p_2_transport.public_key().to_vec(),
                                pre_signature);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(pre_signatures)
}

/// Create a new session and then perform
/// signature generation
async fn gg20_sign_online(
    server: &str,
    server_public_key: Vec<u8>,
    parameters: Parameters,
    mut keypairs: Vec<Keypair>,
    mut pre_signatures: HashMap<Vec<u8>, CompletedOfflineStage>,
    message: [u8; 32],
) -> Result<HashMap<Vec<u8>, Signature>> {
    let initiator_key = keypairs.remove(0);
    let participant_key_2 = keypairs.pop().unwrap();
    let sign_participants =
        vec![participant_key_2.public_key().to_vec()];

    // Create new clients for signature generation
    let (client_i, event_loop_i) =
        new_client_with_keypair::<anyhow::Error>(
            server,
            server_public_key.clone(),
            initiator_key,
        )
        .await?;
    let (client_p_2, event_loop_p_2) =
        new_client_with_keypair::<anyhow::Error>(
            server,
            server_public_key.clone(),
            participant_key_2,
        )
        .await?;

    let mut client_i_transport: Transport = client_i.into();
    let mut client_p_2_transport: Transport = client_p_2.into();

    // Each client handshakes with the server
    client_i_transport.connect().await?;
    client_p_2_transport.connect().await?;

    let mut s_i = event_loop_i.run();
    let mut s_p_2 = event_loop_p_2.run();

    let mut sessions: Vec<SessionState> = Vec::new();

    let mut client_i_session =
        SessionInitiator::new(client_i_transport, sign_participants);
    let mut client_p_2_session =
        SessionParticipant::new(client_p_2_transport);

    // Prepare the sessions for each party
    loop {
        if sessions.len() == 2 {
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

    // Prepare for pre-signature generation
    let client_i_transport: Transport = client_i_session.into();
    let client_p_2_transport: Transport = client_p_2_session.into();

    let session_i = sessions.remove(0);
    let session_p_2 = sessions.remove(0);

    let offline_stage_i = pre_signatures
        .remove(client_i_transport.public_key())
        .unwrap();
    let offline_stage_p_2 = pre_signatures
        .remove(client_p_2_transport.public_key())
        .unwrap();

    let mut sign_i = SignatureGenerator::new(
        client_i_transport.clone(),
        parameters.clone(),
        session_i,
        offline_stage_i,
        message,
    )?;
    let mut sign_p_2 = SignatureGenerator::new(
        client_p_2_transport.clone(),
        parameters.clone(),
        session_p_2,
        offline_stage_p_2,
        message,
    )?;

    // Each party starts signature generation.
    sign_i.execute().await?;
    sign_p_2.execute().await?;

    let mut signatures: HashMap<Vec<u8>, Signature> = HashMap::new();

    loop {
        if signatures.len() == 2 {
            break;
        }
        select! {
            event = s_i.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(signature) =
                            sign_i.handle_event(event).await? {
                            signatures.insert(
                                client_i_transport.public_key().to_vec(),
                                signature);
                        }
                    }
                    _ => {}
                }
            },
            event = s_p_2.next().fuse() => {
                match event {
                    Some(event) => {
                        let event = event?;
                        if let Some(signature) =
                            sign_p_2.handle_event(event).await? {
                            signatures.insert(
                                client_p_2_transport.public_key().to_vec(),
                                signature);
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(signatures)
}
