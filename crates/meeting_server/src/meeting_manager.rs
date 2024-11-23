use polysig_protocol::{PublicKeys, MeetingId, UserId};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};

/// Manages a collection of meeting rooms.
#[derive(Default)]
pub struct MeetingManager {
    rooms: HashMap<MeetingId, MeetingRoom>,
}

impl MeetingManager {
    /// Create a new meeting room.
    pub fn new_room(
        &mut self,
        owner_id: UserId,
        slots: HashSet<UserId>,
    ) -> MeetingId {
        let meeting_id = MeetingId::new_v4();
        let slots: HashMap<UserId, Option<(u64, PublicKeys)>> =
            slots.into_iter().map(|id| (id, None)).collect();

        let meeting = MeetingRoom {
            owner_id,
            slots,
            last_access: SystemTime::now(),
        };

        self.rooms.insert(meeting_id, meeting);
        meeting_id
    }

    /// Remove a meeting room.
    pub fn remove_room(
        &mut self,
        id: &MeetingId,
    ) -> Option<MeetingRoom> {
        self.rooms.remove(id)
    }

    /// Mutable meeting room.
    pub fn room_mut(
        &mut self,
        id: &MeetingId,
    ) -> Option<&mut MeetingRoom> {
        self.rooms.get_mut(id)
    }

    /// Keys of meetings that have expired.
    pub fn expired_keys(&self, timeout: u64) -> Vec<MeetingId> {
        self.rooms
            .iter()
            .filter(|(_, v)| {
                let now = SystemTime::now();
                let ttl = Duration::from_millis(timeout * 1000);
                if let Some(current) = v.last_access.checked_add(ttl)
                {
                    current < now
                } else {
                    false
                }
            })
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
    }
}

/// Meeting point information.
#[derive(Debug)]
pub(crate) struct MeetingRoom {
    /// Owner that created the meeting.
    #[allow(dead_code)]
    pub(crate) owner_id: UserId,
    /// Map of user identifiers to public keys.
    pub(crate) slots: HashMap<UserId, Option<(u64, PublicKeys)>>,
    /// Last access time so the server can reap
    /// stale meetings.
    last_access: SystemTime,
}

impl MeetingRoom {
    /// Add a participant to this meeting.
    pub fn join(
        &mut self,
        user_id: UserId,
        conn_id: u64,
        data: PublicKeys,
    ) {
        self.slots.insert(user_id, Some((conn_id, data)));
        self.last_access = SystemTime::now();
    }

    /// Whether this meeting point is full.
    pub fn is_full(&self) -> bool {
        self.slots.values().all(|s| s.is_some())
    }
}
