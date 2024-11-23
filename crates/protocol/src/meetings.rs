use crate::UserId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

/// Identifier for meeting points.
pub type MeetingId = uuid::Uuid;

/// Public keys for a participant.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeys {
    /// Public key for the noise transport.
    pub public_key: Vec<u8>,
    /// Verifying key.
    pub verifying_key: Vec<u8>,
    /// Optional application specific associated data.
    pub associated_data: Option<Value>,
}

/// Messages for the meeting server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MeetingRequest {
    /// Create a meeting room.
    NewRoom {
        /// Owner identifier.
        owner_id: UserId,
        /// Slots for all participants.
        slots: HashSet<UserId>,
    },
    /// Join a meeting room.
    JoinRoom {
        /// Meeting identifier.
        meeting_id: MeetingId,
        /// User identifier.
        user_id: UserId,
        /// Data for this participant.
        data: PublicKeys,
    },
}

/// Messages for the meeting client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MeetingResponse {
    /// Meeting room was created.
    RoomCreated {
        /// Meeting identifier.
        meeting_id: MeetingId,
        /// Owner identifier.
        owner_id: UserId,
    },
    /// Meeting room is ready.
    RoomReady {
        /// Participants that have joined the room.
        participants: Vec<(UserId, PublicKeys)>,
    },
}
