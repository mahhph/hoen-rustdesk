//! Durable metadata-only outbox for the Hoen mailbox session-history API.
//!
//! No identity verification, credential storage, or RustDesk hooks
//! are provided. A caller must obtain the client identity from an authenticated
//! enrollment, provision a private directory and send each session serially. The
//! mailbox backend supports configurable enrolled principals; the caller must
//! resolve a verified principal before creating a history event.

pub mod delivery;
mod tls_pin;

use std::{fmt, path::Path, time::Duration};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_IDENTITY_BYTES: usize = 64;
const MAX_CAPACITY: usize = 100_000;

#[derive(Debug)]
pub enum Error {
    InvalidIdentity,
    InvalidCapacity,
    Full,
    EventIdConflict,
    InvalidTransition,
    MigrationRequired,
    NotHead,
    Storage(rusqlite::Error),
    Corrupt,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "invalid mailbox identity",
            Self::InvalidCapacity => "invalid outbox capacity",
            Self::Full => "history outbox is full",
            Self::EventIdConflict => "history event ID conflict",
            Self::InvalidTransition => "invalid history session transition",
            Self::MigrationRequired => "history outbox requires migration",
            Self::NotHead => "history event is not the next pending event for its session",
            Self::Storage(_) => "history outbox storage error",
            Self::Corrupt => "invalid history outbox data",
        })
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            _ => None,
        }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

/// The narrow allowed reason vocabulary; never store a raw error or close string.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Normal,
    UserDisconnect,
    NetworkError,
    AuthenticationFailed,
    ProtocolError,
    HostError,
    ViewerError,
    Timeout,
    Cancelled,
}

/// This value must come from the caller's authenticated, enrolled identity mapping.
/// Validation prevents accidental arbitrary text or JSON from entering the outbox;
/// it does not establish that the identity is genuine.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct MailboxIdentity(String);
impl MailboxIdentity {
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() > MAX_IDENTITY_BYTES
            || value == "operator"
            || !value.as_bytes()[0].is_ascii_lowercase()
            || !value
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MailboxIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// Host-authoritative connected event; caller must already have verified the peer.
    Create {
        client: MailboxIdentity,
    },
    Heartbeat,
    Ended {
        reason: Reason,
    },
    Failed {
        reason: Reason,
    },
}

/// IDs are generated once, before enqueue; retry with the same value after an ambiguous outcome.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    session_id: Uuid,
    event_id: Uuid,
    kind: EventKind,
}
impl Event {
    pub fn create(client: MailboxIdentity) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            kind: EventKind::Create { client },
        }
    }
    pub fn heartbeat(session_id: Uuid) -> Self {
        Self::new(session_id, EventKind::Heartbeat)
    }
    pub fn ended(session_id: Uuid, reason: Reason) -> Self {
        Self::new(session_id, EventKind::Ended { reason })
    }
    pub fn failed(session_id: Uuid, reason: Reason) -> Self {
        Self::new(session_id, EventKind::Failed { reason })
    }
    fn new(session_id: Uuid, kind: EventKind) -> Self {
        Self {
            session_id,
            event_id: Uuid::new_v4(),
            kind,
        }
    }
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }
    pub fn event_id(&self) -> Uuid {
        self.event_id
    }
    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    /// Relative mailbox endpoint; no server address or credentials are stored.
    pub fn endpoint(&self) -> String {
        match self.kind {
            EventKind::Create { .. } => "/v1/remote-sessions".to_owned(),
            _ => format!("/v1/remote-sessions/{}/events", self.session_id),
        }
    }
    /// Deterministic JSON request body for the mailbox's current event contract.
    pub fn body(&self) -> Result<String, Error> {
        let body = match &self.kind {
            EventKind::Create { client } => {
                serde_json::json!({"sessionId":self.session_id,"eventId":self.event_id,"client":client.as_str(),"initiatorRole":"host"})
            }
            EventKind::Heartbeat => serde_json::json!({"eventId":self.event_id,"type":"heartbeat"}),
            EventKind::Ended { reason } => {
                serde_json::json!({"eventId":self.event_id,"type":"ended","reason":reason})
            }
            EventKind::Failed { reason } => {
                serde_json::json!({"eventId":self.event_id,"type":"failed","reason":reason})
            }
        };
        serde_json::to_string(&body).map_err(|_| Error::Corrupt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueResult {
    Inserted,
    AlreadyPending,
}

/// Exact persisted request. Credentials and the server URL are supplied separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    pub event: Event,
    pub endpoint: String,
    pub body: String,
}

/// Synchronous SQLite access: run on a dedicated worker, never on an async runtime thread.
/// Provision an access-restricted directory before opening; this crate does not configure ACLs.
pub struct Outbox {
    db: Connection,
    capacity: usize,
}
impl Outbox {
    pub fn open(path: &Path, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(Error::InvalidCapacity);
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            let old: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='pending_history')", [], |row| row.get(0))?;
            // Earlier prototypes did not preserve active sessions after their create
            // was acknowledged; they cannot be migrated automatically without loss.
            if old {
                return Err(Error::MigrationRequired);
            }
            tx.execute_batch(
                "CREATE TABLE pending_history (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                body TEXT NOT NULL
              );
              CREATE INDEX pending_history_session ON pending_history(session_id, seq);
              CREATE TABLE history_sessions (
                session_id TEXT PRIMARY KEY,
                terminal_event_id TEXT
              );
              CREATE TABLE history_config (id INTEGER PRIMARY KEY CHECK(id=1), capacity INTEGER NOT NULL);
              PRAGMA user_version=1;",
            )?;
            tx.execute(
                "INSERT INTO history_config(id,capacity) VALUES(1,?)",
                [capacity as i64],
            )?;
        } else if version != 1 {
            return Err(Error::MigrationRequired);
        }
        // All processes sharing one database must enforce the same capacity.
        let configured: i64 = tx.query_row(
            "SELECT capacity FROM history_config WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        if configured != capacity as i64 {
            return Err(Error::InvalidCapacity);
        }
        let used: i64 = tx.query_row("SELECT (SELECT COUNT(*) FROM pending_history) + (SELECT COUNT(*) FROM history_sessions WHERE terminal_event_id IS NULL)", [], |row| row.get(0))?;
        if used > capacity as i64 {
            return Err(Error::InvalidCapacity);
        }
        tx.commit()?;
        Ok(Self { db, capacity })
    }

    /// A create consumes one pending slot and reserves one terminal slot until
    /// an ended/failed event is enqueued. Other events require a known active
    /// session. No event is evicted; `AlreadyPending` allows an exact retry.
    pub fn enqueue(&mut self, event: &Event) -> Result<EnqueueResult, Error> {
        if event.session_id.get_version_num() != 4
            || event.event_id.get_version_num() != 4
            || event.session_id.get_variant() != uuid::Variant::RFC4122
            || event.event_id.get_variant() != uuid::Variant::RFC4122
        {
            return Err(Error::Corrupt);
        }
        if let EventKind::Create { client } = &event.kind {
            MailboxIdentity::new(client.as_str())?;
        }
        let json = serde_json::to_string(event).map_err(|_| Error::Corrupt)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT event_json FROM pending_history WHERE event_id=?",
                [event.event_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == json {
                Ok(EnqueueResult::AlreadyPending)
            } else {
                Err(Error::EventIdConflict)
            };
        }
        let state: Option<Option<String>> = tx
            .query_row(
                "SELECT terminal_event_id FROM history_sessions WHERE session_id=?",
                [event.session_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let used: i64 = tx.query_row("SELECT (SELECT COUNT(*) FROM pending_history) + (SELECT COUNT(*) FROM history_sessions WHERE terminal_event_id IS NULL)", [], |row| row.get(0))?;
        match &event.kind {
            EventKind::Create { .. } => {
                if state.is_some() {
                    return Err(Error::InvalidTransition);
                }
                if used + 2 > self.capacity as i64 {
                    return Err(Error::Full);
                }
                tx.execute(
                    "INSERT INTO history_sessions(session_id, terminal_event_id) VALUES(?, NULL)",
                    [event.session_id.to_string()],
                )?;
            }
            EventKind::Heartbeat => {
                if state != Some(None) {
                    return Err(Error::InvalidTransition);
                }
                if used + 1 > self.capacity as i64 {
                    return Err(Error::Full);
                }
            }
            EventKind::Ended { .. } | EventKind::Failed { .. } => {
                if state != Some(None) {
                    return Err(Error::InvalidTransition);
                }
                // The new pending event replaces this session's reserved slot.
                tx.execute(
                    "UPDATE history_sessions SET terminal_event_id=? WHERE session_id=?",
                    params![event.event_id.to_string(), event.session_id.to_string()],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO pending_history(session_id,event_id,event_json,endpoint,body) VALUES(?1,?2,?3,?4,?5)",
            params![
                event.session_id.to_string(),
                event.event_id.to_string(),
                json,
                event.endpoint(),
                event.body()?
            ],
        )?;
        tx.commit()?;
        Ok(EnqueueResult::Inserted)
    }

    /// Exact persisted request bytes, unchanged across retries or application upgrades.
    /// No lease is acquired; the caller must serialize sends for each session.
    pub fn next_request_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<PendingRequest>, Error> {
        let row: Option<(String, String, String)> = self.db.query_row(
            "SELECT event_json,endpoint,body FROM pending_history WHERE session_id=? ORDER BY seq LIMIT 1",
            [session_id.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))
        ).optional()?;
        row.map(|(json, endpoint, body)| {
            let event: Event = serde_json::from_str(&json).map_err(|_| Error::Corrupt)?;
            if event.session_id != session_id {
                return Err(Error::Corrupt);
            }
            if let EventKind::Create { client } = &event.kind {
                MailboxIdentity::new(client.as_str()).map_err(|_| Error::Corrupt)?;
            }
            Ok(PendingRequest {
                event,
                endpoint,
                body,
            })
        })
        .transpose()
    }

    /// Oldest event globally. No claim/lease is created; sending must be serialized by the caller.
    pub fn next(&self) -> Result<Option<Event>, Error> {
        self.query_next(None)
    }
    /// Oldest remaining event for one session.
    pub fn next_for_session(&self, session_id: Uuid) -> Result<Option<Event>, Error> {
        self.query_next(Some(session_id))
    }
    fn query_next(&self, session_id: Option<Uuid>) -> Result<Option<Event>, Error> {
        let json: Option<String> = match session_id {
            Some(id) => self.db.query_row("SELECT event_json FROM pending_history WHERE session_id=? ORDER BY seq LIMIT 1", [id.to_string()], |r| r.get(0)).optional()?,
            None => self.db.query_row("SELECT event_json FROM pending_history ORDER BY seq LIMIT 1", [], |r| r.get(0)).optional()?,
        };
        json.map(|s| {
            let event: Event = serde_json::from_str(&s).map_err(|_| Error::Corrupt)?;
            if let EventKind::Create { client } = &event.kind {
                MailboxIdentity::new(client.as_str()).map_err(|_| Error::Corrupt)?;
            }
            Ok(event)
        })
        .transpose()
    }
    /// Call only after the mailbox confirms this exact event. Out-of-order acks fail.
    pub fn acknowledge(&mut self, session_id: Uuid, event_id: Uuid) -> Result<(), Error> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let first: Option<String> = tx
            .query_row(
                "SELECT event_id FROM pending_history WHERE session_id=? ORDER BY seq LIMIT 1",
                [session_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if first.as_deref() != Some(event_id.to_string().as_str()) {
            return Err(Error::NotHead);
        }
        tx.execute(
            "DELETE FROM pending_history WHERE session_id=? AND event_id=?",
            params![session_id.to_string(), event_id.to_string()],
        )?;
        tx.execute(
            "DELETE FROM history_sessions WHERE session_id=? AND terminal_event_id=?",
            params![session_id.to_string(), event_id.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Number of terminal slots reserved for sessions that have no terminal event yet.
    pub fn reserved_count(&self) -> Result<usize, Error> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM history_sessions WHERE terminal_event_id IS NULL",
            [],
            |r| r.get(0),
        )?;
        usize::try_from(count).map_err(|_| Error::Corrupt)
    }
    pub fn pending_count(&self) -> Result<usize, Error> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM pending_history", [], |r| r.get(0))?;
        usize::try_from(count).map_err(|_| Error::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn restart_lost_ack_retry_and_ordering() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("outbox.sqlite");
        let create = Event::create(MailboxIdentity::new("windows-hoenlenovo").unwrap());
        let heartbeat = Event::heartbeat(create.session_id());
        let ended = Event::ended(create.session_id(), Reason::UserDisconnect);
        let original_body = create.body().unwrap();
        {
            let mut outbox = Outbox::open(&db, 10).unwrap();
            assert_eq!(outbox.enqueue(&create).unwrap(), EnqueueResult::Inserted);
            assert_eq!(
                outbox.enqueue(&create).unwrap(),
                EnqueueResult::AlreadyPending
            );
            outbox.enqueue(&heartbeat).unwrap();
            outbox.enqueue(&ended).unwrap();
            assert!(matches!(
                outbox.acknowledge(create.session_id(), ended.event_id()),
                Err(Error::NotHead)
            ));
        }
        {
            let mut outbox = Outbox::open(&db, 10).unwrap();
            let retry = outbox.next().unwrap().unwrap();
            assert_eq!(retry, create);
            assert_eq!(retry.body().unwrap(), original_body);
            let stored = outbox
                .next_request_for_session(create.session_id())
                .unwrap()
                .unwrap();
            assert_eq!(stored.body, original_body);
            assert_eq!(stored.event, retry);
            assert_eq!(retry.endpoint(), "/v1/remote-sessions");
            // Server response was lost; retry retains exactly the same event UUID and body.
            assert_eq!(
                outbox.next().unwrap().unwrap().body().unwrap(),
                original_body
            );
            outbox
                .acknowledge(create.session_id(), create.event_id())
                .unwrap();
            assert_eq!(
                outbox.next_for_session(create.session_id()).unwrap(),
                Some(heartbeat.clone())
            );
            outbox
                .acknowledge(create.session_id(), heartbeat.event_id())
                .unwrap();
            assert_eq!(outbox.next().unwrap(), Some(ended.clone()));
        }
        let mut outbox = Outbox::open(&db, 10).unwrap();
        assert_eq!(outbox.next().unwrap(), Some(ended.clone()));
        outbox
            .acknowledge(create.session_id(), ended.event_id())
            .unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 0);
    }

    #[test]
    fn reservation_survives_restart_and_terminal_fits_at_capacity() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("outbox.sqlite");
        let create = Event::create(MailboxIdentity::new("another-user").unwrap());
        let beat = Event::heartbeat(create.session_id());
        let ended = Event::ended(create.session_id(), Reason::Normal);
        {
            let mut outbox = Outbox::open(&db, 3).unwrap();
            outbox.enqueue(&create).unwrap();
            outbox
                .acknowledge(create.session_id(), create.event_id())
                .unwrap();
            outbox.enqueue(&beat).unwrap();
        }
        assert!(matches!(Outbox::open(&db, 1), Err(Error::InvalidCapacity)));
        let mut outbox = Outbox::open(&db, 3).unwrap();
        assert_eq!(outbox.reserved_count().unwrap(), 1);
        let beat2 = Event::heartbeat(create.session_id());
        outbox.enqueue(&beat2).unwrap();
        assert!(matches!(
            outbox.enqueue(&Event::heartbeat(create.session_id())),
            Err(Error::Full)
        ));
        assert!(matches!(
            outbox.enqueue(&Event::create(MailboxIdentity::new("other").unwrap())),
            Err(Error::Full)
        ));
        outbox.enqueue(&ended).unwrap();
        assert_eq!(outbox.reserved_count().unwrap(), 0);
        assert_eq!(outbox.pending_count().unwrap(), 3);
        assert_eq!(
            outbox.enqueue(&ended).unwrap(),
            EnqueueResult::AlreadyPending
        );
        assert!(matches!(
            outbox.enqueue(&Event::heartbeat(create.session_id())),
            Err(Error::InvalidTransition)
        ));
        assert!(matches!(
            outbox.enqueue(&Event::failed(create.session_id(), Reason::HostError)),
            Err(Error::InvalidTransition)
        ));
        outbox
            .acknowledge(create.session_id(), beat.event_id())
            .unwrap();
        outbox
            .acknowledge(create.session_id(), beat2.event_id())
            .unwrap();
        outbox
            .acknowledge(create.session_id(), ended.event_id())
            .unwrap();
        assert!(matches!(
            outbox.enqueue(&Event::heartbeat(create.session_id())),
            Err(Error::InvalidTransition)
        ));
        assert!(matches!(
            outbox.enqueue(&Event::ended(Uuid::new_v4(), Reason::Normal)),
            Err(Error::InvalidTransition)
        ));
        assert_eq!(outbox.pending_count().unwrap(), 0);
    }

    #[test]
    fn legacy_database_requires_explicit_migration_without_deleting_events() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("legacy.sqlite");
        let legacy = Connection::open(&db).unwrap();
        legacy.execute_batch("CREATE TABLE pending_history(event_id TEXT); INSERT INTO pending_history VALUES('existing');").unwrap();
        drop(legacy);
        assert!(matches!(
            Outbox::open(&db, 10),
            Err(Error::MigrationRequired)
        ));
        let check = Connection::open(&db).unwrap();
        assert_eq!(
            check
                .query_row("SELECT COUNT(*) FROM pending_history", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn interleaved_sessions_ack_independently_and_body_is_allowlisted() {
        let dir = tempdir().unwrap();
        let mut outbox = Outbox::open(&dir.path().join("outbox.sqlite"), 5).unwrap();
        let first = Event::create(MailboxIdentity::new("machine-a").unwrap());
        let second = Event::create(MailboxIdentity::new("machine-b").unwrap());
        let end = Event::failed(first.session_id(), Reason::NetworkError);
        outbox.enqueue(&first).unwrap();
        outbox.enqueue(&second).unwrap();
        outbox.enqueue(&end).unwrap();
        outbox
            .acknowledge(second.session_id(), second.event_id())
            .unwrap();
        assert!(matches!(
            outbox.acknowledge(first.session_id(), end.event_id()),
            Err(Error::NotHead)
        ));
        let body: serde_json::Value = serde_json::from_str(&end.body().unwrap()).unwrap();
        assert_eq!(body["reason"], "network_error");
        assert_eq!(body.as_object().unwrap().len(), 3);
        assert!(MailboxIdentity::new("arbitrary message with spaces").is_err());
        for invalid in [
            "operator",
            "UPPER",
            "a_b",
            "a.b",
            "a@b",
            "1abc",
            "",
            &"a".repeat(65),
        ] {
            assert!(MailboxIdentity::new(invalid).is_err());
            let json = serde_json::to_string(invalid).unwrap();
            assert!(serde_json::from_str::<MailboxIdentity>(&json).is_err());
        }
        assert_eq!(
            serde_json::from_str::<MailboxIdentity>("\"windows-hoenlenovo\"")
                .unwrap()
                .as_str(),
            "windows-hoenlenovo"
        );
    }
}
