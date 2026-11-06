//! Dedicated, bounded history persistence and HTTPS delivery worker.
//!
//! Call `begin` only after verified grant authentication and desktop initialization,
//! immediately before admission. A successful reply confirms *local durable enqueue*,
//! not mailbox delivery. Caller must record a terminal failure if subsequent admission
//! fails. A lost reply is ambiguous: do not admit or retry as a new session. Pending
//! outbox rows survive worker restart; missing terminal events are never fabricated.
//! The caller must provision an access-restricted outbox directory and keep one worker
//! per outbox. Dropping all handles stops delivery, leaving pending events on disk.
use hbb_common::{sodiumoxide::randombytes, tokio::sync::oneshot};
use hoen_mailbox_auth::mailbox::ConsumedGrant;
use hoen_mailbox_history::{
    delivery::{ApiToken, DeliveryError, MailboxDelivery},
    Error as OutboxError, Event, MailboxIdentity, Outbox, Reason,
};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const QUEUE_CAPACITY: usize = 32;
const MIN_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(crate) enum WorkerError {
    Unavailable,
    QueueFull,
    Credential,
    Outbox(OutboxError),
    Delivery(DeliveryError),
    /// The reply was lost after submission; the operation may have committed.
    Unconfirmed,
    DeliveryBlocked,
}
impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("history worker unavailable"),
            Self::QueueFull => f.write_str("history worker queue is full"),
            Self::Credential => f.write_str("history credential unavailable"),
            Self::Outbox(e) => write!(f, "history outbox: {e}"),
            Self::Delivery(e) => write!(f, "history delivery: {e}"),
            Self::Unconfirmed => f.write_str("history operation outcome is unconfirmed"),
            Self::DeliveryBlocked => f.write_str("history delivery requires intervention"),
        }
    }
}
impl std::error::Error for WorkerError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryState {
    Ready,
    RetryPending,
    BlockedPermanent(u16),
    BlockedInvalid,
    StorageFailed,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Status {
    pub pending: usize,
    pub reserved: usize,
    pub delivery: DeliveryState,
}

type Reply<T> = oneshot::Sender<Result<T, WorkerError>>;
enum Request {
    Begin(Event, Reply<Uuid>),
    Append(Event, Reply<()>),
    Status(Reply<Status>),
}

/// A successful `begin` returns the unique connection/session ID. Caller must
/// invoke it once per verified connection and never reuse the returned ID.
#[derive(Clone)]
pub(crate) struct HistoryWorker(SyncSender<Request>);
/// The same prepared create must be retried after an ambiguous enqueue; never
/// generate another session ID merely because its reply was lost.
pub(crate) struct SessionStart(Event);
impl SessionStart {
    pub fn new(grant: &ConsumedGrant) -> Result<Self, WorkerError> {
        let client = MailboxIdentity::new(grant.viewer.as_str()).map_err(WorkerError::Outbox)?;
        Ok(Self(Event::create(client)))
    }
    pub fn session_id(&self) -> Uuid {
        self.0.session_id()
    }
}
/// Retain the same intent across ambiguous enqueue attempts to preserve its
/// event ID and body. The outbox rejects new events after a terminal intent.
pub(crate) struct HistoryIntent(Event);
impl HistoryIntent {
    pub fn heartbeat(id: Uuid) -> Self {
        Self(Event::heartbeat(id))
    }
    pub fn ended(id: Uuid, reason: Reason) -> Self {
        Self(Event::ended(id, reason))
    }
    pub fn failed(id: Uuid, reason: Reason) -> Self {
        Self(Event::failed(id, reason))
    }
}
impl HistoryWorker {
    /// `load_token` is called and the blocking HTTPS client is created/dropped on
    /// the worker thread, never inside a Tokio runtime. It must obtain the token
    /// from the appropriate protected host identity; never use argv or logs.
    pub async fn start<F>(
        path: PathBuf,
        capacity: usize,
        url: String,
        root_pem: Vec<u8>,
        load_token: F,
    ) -> Result<Self, WorkerError>
    where
        F: FnOnce() -> Result<ApiToken, WorkerError> + Send + 'static,
    {
        Self::start_with_pin(path, capacity, url, root_pem, load_token, None).await
    }
    pub async fn start_with_pin<F>(
        path: PathBuf,
        capacity: usize,
        url: String,
        root_pem: Vec<u8>,
        load_token: F,
        pin: Option<[u8; 32]>,
    ) -> Result<Self, WorkerError>
    where
        F: FnOnce() -> Result<ApiToken, WorkerError> + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (started, ready) = oneshot::channel();
        thread::Builder::new()
            .name("hoen-history".into())
            .spawn(move || {
                let init = (|| {
                    let outbox = Outbox::open(&path, capacity).map_err(WorkerError::Outbox)?;
                    let token = load_token()?;
                    let delivery = match pin {
                        Some(pin) => MailboxDelivery::new_pinned(&url, &root_pem, token, pin),
                        None => MailboxDelivery::new(&url, &root_pem, token),
                    }.map_err(WorkerError::Delivery)?;
                    Ok::<_, WorkerError>((outbox, delivery))
                })();
                match init {
                    Ok((outbox, delivery)) => {
                        if started.send(Ok(())).is_ok() {
                            run(outbox, delivery, receiver);
                        }
                    }
                    Err(error) => {
                        let _ = started.send(Err(error));
                    }
                }
            })
            .map_err(|_| WorkerError::Unavailable)?;
        ready.await.map_err(|_| WorkerError::Unavailable)??;
        Ok(Self(sender))
    }
    fn submit(&self, request: Request) -> Result<(), WorkerError> {
        self.0.try_send(request).map_err(|error| match error {
            TrySendError::Full(_) => WorkerError::QueueFull,
            TrySendError::Disconnected(_) => WorkerError::Unavailable,
        })
    }
    /// Prepare from a successful `consume_proof` on this exact connection.
    /// Keep the start object until the enqueue outcome is known.
    pub async fn begin(&self, start: &SessionStart) -> Result<Uuid, WorkerError> {
        let (tx, rx) = oneshot::channel();
        self.submit(Request::Begin(start.0.clone(), tx))?;
        rx.await.map_err(|_| WorkerError::Unconfirmed)?
    }
    pub async fn record(&self, intent: &HistoryIntent) -> Result<(), WorkerError> {
        let (tx, rx) = oneshot::channel();
        self.submit(Request::Append(intent.0.clone(), tx))?;
        rx.await.map_err(|_| WorkerError::Unconfirmed)?
    }
    pub async fn status(&self) -> Result<Status, WorkerError> {
        let (tx, rx) = oneshot::channel();
        self.submit(Request::Status(tx))?;
        rx.await.map_err(|_| WorkerError::Unconfirmed)?
    }
}

fn enqueue(
    outbox: &mut Outbox,
    event: &Event,
    state: &mut DeliveryState,
) -> Result<(), WorkerError> {
    match outbox.enqueue(event) {
        Ok(_) => Ok(()),
        Err(error) => {
            if matches!(
                error,
                OutboxError::Storage(_) | OutboxError::Corrupt | OutboxError::MigrationRequired
            ) {
                *state = DeliveryState::StorageFailed;
            }
            Err(WorkerError::Outbox(error))
        }
    }
}
fn retry_delay(attempt: u32) -> Duration {
    let upper_ms = (MIN_RETRY.as_millis() as u64)
        .saturating_mul(1u64 << attempt.min(5))
        .min(MAX_RETRY.as_millis() as u64);
    let mut bytes = [0u8; 8];
    randombytes::randombytes_into(&mut bytes);
    // Equal jitter, bounded away from zero and never above MAX_RETRY.
    Duration::from_millis(upper_ms / 2 + u64::from_le_bytes(bytes) % (upper_ms / 2 + 1))
}
fn run(mut outbox: Outbox, delivery: MailboxDelivery, receiver: Receiver<Request>) {
    let mut state = DeliveryState::Ready;
    let mut retry_at = Instant::now();
    let mut attempt = 0u32;
    loop {
        let wait = if matches!(state, DeliveryState::Ready | DeliveryState::RetryPending) {
            retry_at
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(1))
        } else {
            Duration::from_secs(1)
        };
        match receiver.recv_timeout(wait) {
            Ok(Request::Begin(event, reply)) => {
                if reply.is_closed() {
                    continue;
                }
                if matches!(
                    state,
                    DeliveryState::BlockedPermanent(_)
                        | DeliveryState::BlockedInvalid
                        | DeliveryState::StorageFailed
                ) {
                    let _ = reply.send(Err(WorkerError::DeliveryBlocked));
                } else {
                    let result =
                        enqueue(&mut outbox, &event, &mut state).map(|_| event.session_id());
                    if let Err(Ok(id)) = reply.send(result) {
                        // The caller abandoned admission after the durable write.
                        // The outbox reserved this terminal slot at creation.
                        if enqueue(
                            &mut outbox,
                            &Event::failed(id, Reason::Cancelled),
                            &mut state,
                        )
                        .is_err()
                            && state != DeliveryState::StorageFailed
                        {
                            state = DeliveryState::BlockedInvalid;
                        }
                    }
                }
            }
            Ok(Request::Append(event, reply)) => {
                let _ = reply.send(enqueue(&mut outbox, &event, &mut state));
            }
            Ok(Request::Status(reply)) => {
                let status = outbox
                    .pending_count()
                    .and_then(|pending| {
                        outbox.reserved_count().map(|reserved| Status {
                            pending,
                            reserved,
                            delivery: state,
                        })
                    })
                    .map_err(WorkerError::Outbox);
                let _ = reply.send(status);
            }
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        if !matches!(state, DeliveryState::Ready | DeliveryState::RetryPending)
            || Instant::now() < retry_at
        {
            continue;
        }
        match outbox.next() {
            Ok(Some(event)) => match delivery.deliver_next(&mut outbox, event.session_id()) {
                Ok(_) => {
                    state = DeliveryState::Ready;
                    attempt = 0;
                    retry_at = Instant::now();
                }
                Err(DeliveryError::Retryable) => {
                    state = DeliveryState::RetryPending;
                    retry_at = Instant::now() + retry_delay(attempt);
                    attempt = attempt.saturating_add(1);
                }
                Err(DeliveryError::Permanent(status)) => {
                    state = DeliveryState::BlockedPermanent(status)
                }
                Err(DeliveryError::Storage(_)) => state = DeliveryState::StorageFailed,
                Err(_) => state = DeliveryState::BlockedInvalid,
            },
            Ok(None) => {
                state = DeliveryState::Ready;
                retry_at = Instant::now() + Duration::from_secs(1);
            }
            Err(_) => state = DeliveryState::StorageFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn pinned_history_client_rejects_invalid_trust_before_delivery() {
        let path = std::env::temp_dir().join(format!("hoen-history-pinned-{}.sqlite", Uuid::new_v4()));
        let result = HistoryWorker::start_with_pin(path.clone(), 4, "https://localhost/".into(), Vec::new(), || ApiToken::new("A".repeat(43)).map_err(|_| WorkerError::Credential), Some([7;32])).await;
        assert!(matches!(result, Err(WorkerError::Delivery(DeliveryError::InvalidConfiguration))));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bounded_retry_delays_never_spin_or_exceed_cap() {
        for attempt in 0..16 {
            for _ in 0..10 {
                let delay = retry_delay(attempt);
                assert!(delay >= Duration::from_millis(500));
                assert!(delay <= MAX_RETRY);
            }
        }
    }

    #[test]
    fn prepared_intents_reuse_ids_and_do_not_accept_freeform_messages() {
        let id = Uuid::new_v4();
        let intent = HistoryIntent::failed(id, Reason::NetworkError);
        let retry = intent.0.clone();
        assert_eq!(retry.event_id(), intent.0.event_id());
        assert_eq!(retry.body().unwrap(), intent.0.body().unwrap());
        assert_eq!(retry.session_id(), id);
        assert!(retry.body().unwrap().contains("network_error"));
    }

    #[test]
    fn create_and_terminal_survive_reopening_in_order() {
        let path =
            std::env::temp_dir().join(format!("hoen-history-worker-{}.sqlite", Uuid::new_v4()));
        let create = Event::create(MailboxIdentity::new("viewer-test").unwrap());
        let terminal = Event::ended(create.session_id(), Reason::Normal);
        let mut state = DeliveryState::Ready;
        {
            let mut outbox = Outbox::open(&path, 4).unwrap();
            enqueue(&mut outbox, &create, &mut state).unwrap();
            enqueue(&mut outbox, &create, &mut state).unwrap();
            enqueue(&mut outbox, &terminal, &mut state).unwrap();
        }
        {
            let mut outbox = Outbox::open(&path, 4).unwrap();
            assert_eq!(
                outbox.next().unwrap().unwrap().event_id(),
                create.event_id()
            );
            outbox
                .acknowledge(create.session_id(), create.event_id())
                .unwrap();
            assert_eq!(
                outbox.next().unwrap().unwrap().event_id(),
                terminal.event_id()
            );
            outbox
                .acknowledge(terminal.session_id(), terminal.event_id())
                .unwrap();
            assert_eq!(outbox.pending_count().unwrap(), 0);
        }
        let _ = std::fs::remove_file(path);
    }
}
