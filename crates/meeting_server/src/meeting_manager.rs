use polysig_protocol::{MeetingData, MeetingId, UserId};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};

/// Manages a collection of meeting points.
#[derive(Default)]
pub struct MeetingManager {
    meetings: HashMap<MeetingId, Meeting>,
}

impl MeetingManager {
    /// Create a new meeting point.
    pub fn new_meeting(
        &mut self,
        owner_id: UserId,
        slots: HashSet<UserId>,
        conn_id: u64,
        data: MeetingData,
    ) -> MeetingId {
        let meeting_id = MeetingId::new_v4();
        let slots: HashMap<UserId, Option<(u64, MeetingData)>> =
            slots.into_iter().map(|id| (id, None)).collect();

        let mut meeting = Meeting {
            slots,
            last_access: SystemTime::now(),
        };
        meeting.join(owner_id, conn_id, data);

        self.meetings.insert(meeting_id, meeting);
        meeting_id
    }

    /// Remove a meeting.
    pub fn remove_meeting(
        &mut self,
        id: &MeetingId,
    ) -> Option<Meeting> {
        self.meetings.remove(id)
    }

    /// Get a meeting.
    pub fn get_meeting(&self, id: &MeetingId) -> Option<&Meeting> {
        self.meetings.get(id)
    }

    /// Get a mutable meeting.
    pub fn get_meeting_mut(
        &mut self,
        id: &MeetingId,
    ) -> Option<&mut Meeting> {
        self.meetings.get_mut(id)
    }

    /// Get the keys of meetings that have expired.
    pub fn expired_keys(&self, timeout: u64) -> Vec<MeetingId> {
        self.meetings
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
pub struct Meeting {
    /// Map of user identifiers to public keys.
    pub(crate) slots: HashMap<UserId, Option<(u64, MeetingData)>>,
    /// Last access time so the server can reap
    /// stale meetings.
    last_access: SystemTime,
}

impl Meeting {
    /// Add a participant to this meeting.
    pub fn join(
        &mut self,
        user_id: UserId,
        conn_id: u64,
        data: MeetingData,
    ) {
        self.slots.insert(user_id, Some((conn_id, data)));
        self.last_access = SystemTime::now();
    }

    /// Whether this meeting point is full.
    pub fn is_full(&self) -> bool {
        self.slots.values().all(|s| s.is_some())
    }
}
