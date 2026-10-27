//! Persistent admission control. Money is represented in integer micro-dollars.
//! A process crash never turns an uncertain external charge into free capacity.

use crate::config::Limits;
use crate::error::{ErrorCode, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use uuid::Uuid;

#[path = "budget_guard.rs"]
mod guard;
pub use guard::{
    check_guarded_host, open_guarded, provision_guarded, run_guard_witness, validate_guarded_state,
};

pub use crate::api::RequestedLimits;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobLimits {
    pub seconds: u64,
    pub bytes: u64,
    pub micro_usd: u64,
    pub queries: u32,
    pub documents: u32,
    pub requests: u32,
    pub pdf_pages: u32,
    pub browser_actions: u32,
}

impl RequestedLimits {
    pub fn violations(&self, operator: &Limits) -> Vec<crate::error::LimitViolation> {
        use crate::error::{LimitField, LimitViolation};
        [
            (LimitField::Seconds, self.seconds, 1, operator.job_seconds),
            (LimitField::Bytes, self.bytes, 0, operator.job_bytes),
            (
                LimitField::MicroUsd,
                self.micro_usd,
                0,
                operator.job_micro_usd,
            ),
            (
                LimitField::Queries,
                self.queries.map(u64::from),
                0,
                u64::from(operator.queries),
            ),
            (
                LimitField::Documents,
                self.documents.map(u64::from),
                0,
                u64::from(operator.documents),
            ),
            (
                LimitField::Requests,
                self.requests.map(u64::from),
                0,
                u64::from(operator.requests),
            ),
            (
                LimitField::PdfPages,
                self.pdf_pages.map(u64::from),
                0,
                u64::from(operator.pdf_pages),
            ),
            (
                LimitField::BrowserActions,
                self.browser_actions.map(u64::from),
                0,
                u64::from(operator.browser_actions),
            ),
        ]
        .into_iter()
        .filter_map(|(field, requested, minimum, maximum)| {
            requested
                .filter(|value| *value < minimum || *value > maximum)
                .map(|requested| LimitViolation {
                    field,
                    requested,
                    minimum,
                    maximum,
                })
        })
        .collect()
    }

    pub fn resolve(&self, operator: &Limits) -> Result<JobLimits> {
        let limits = JobLimits {
            seconds: self.seconds.unwrap_or(operator.job_seconds),
            bytes: self.bytes.unwrap_or(operator.job_bytes),
            micro_usd: self.micro_usd.unwrap_or(operator.job_micro_usd),
            queries: self.queries.unwrap_or(operator.queries),
            documents: self.documents.unwrap_or(operator.documents),
            requests: self.requests.unwrap_or(operator.requests),
            pdf_pages: self.pdf_pages.unwrap_or(operator.pdf_pages),
            browser_actions: self.browser_actions.unwrap_or(operator.browser_actions),
        };
        if !self.violations(operator).is_empty() {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(limits)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Charge {
    pub bytes: u64,
    pub micro_usd: u64,
    pub requests: u32,
    pub queries: u32,
    pub documents: u32,
    pub pdf_pages: u32,
    pub browser_actions: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Usage {
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub known_micro_usd: u64,
    pub held_micro_usd: u64,
    pub requests: u32,
    pub queries: u32,
    pub documents: u32,
    pub pdf_pages: u32,
    pub browser_actions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Active,
    Completed,
    Cancelled,
    Interrupted,
    Expired,
    Exhausted,
}

impl JobState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
            Self::Expired => "expired",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Job {
    pub id: Uuid,
    pub state: JobState,
    pub created_at: i64,
    pub deadline_at: i64,
    pub limits: JobLimits,
    pub usage: Usage,
}

impl Job {
    /// Remaining job capacity, including all in-flight and uncertain holds.
    /// This does not override job state or the independent UTC-day cost cap.
    pub fn remaining(&self) -> JobLimits {
        let limits = &self.limits;
        let usage = &self.usage;
        JobLimits {
            seconds: (self.deadline_at - Utc::now().timestamp()).max(0) as u64,
            bytes: limits
                .bytes
                .saturating_sub(usage.used_bytes)
                .saturating_sub(usage.reserved_bytes),
            micro_usd: limits
                .micro_usd
                .saturating_sub(usage.known_micro_usd)
                .saturating_sub(usage.held_micro_usd),
            queries: limits.queries.saturating_sub(usage.queries),
            documents: limits.documents.saturating_sub(usage.documents),
            requests: limits.requests.saturating_sub(usage.requests),
            pdf_pages: limits.pdf_pages.saturating_sub(usage.pdf_pages),
            browser_actions: limits.browser_actions.saturating_sub(usage.browser_actions),
        }
    }
}

// A permit is acquired before a reservation can be committed. It remains with
// that reservation until its settlement has been processed, including on drop.
const GUARDED_SETTLEMENTS: usize = 1024;
const SERIALIZED_CONTROLS: usize = 256;

struct Serialization {
    worker: OnceLock<Result<SerializationWorker>>,
    pending: AtomicUsize,
    failed: AtomicBool,
    broken: AtomicBool,
    #[cfg(test)]
    test_guarded: AtomicBool,
    #[cfg(test)]
    test_panic_settlement: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    #[cfg(test)]
    test_panic_after_operation: AtomicBool,
}

impl Serialization {
    fn new() -> Self {
        Self {
            worker: OnceLock::new(),
            pending: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            broken: AtomicBool::new(false),
            #[cfg(test)]
            test_guarded: AtomicBool::new(false),
            #[cfg(test)]
            test_panic_settlement: Mutex::new(None),
            #[cfg(test)]
            test_panic_after_operation: AtomicBool::new(false),
        }
    }

    fn worker(&self, ledger: &Arc<Ledger>) -> Result<&SerializationWorker> {
        let worker = self
            .worker
            .get_or_init(|| SerializationWorker::new(Arc::downgrade(ledger)));
        if worker.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        worker.as_ref().map_err(|error| *error)
    }
}

struct SerializationWorker {
    sender: mpsc::Sender<SerializedOperation>,
    settlements: Arc<Semaphore>,
    controls: Arc<Semaphore>,
    alive: Arc<AtomicBool>,
}

// The receiver owns no ledger or sender, so it exits when the last ledger and
// queued operation are gone. It also never runs on a Tokio runtime worker.
impl SerializationWorker {
    fn new(ledger: Weak<Ledger>) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<SerializedOperation>();
        let alive = Arc::new(AtomicBool::new(true));
        let worker_alive = Arc::clone(&alive);
        std::thread::Builder::new()
            .name("research-ledger".into())
            .spawn(move || {
                struct Alive {
                    alive: Arc<AtomicBool>,
                    ledger: Weak<Ledger>,
                }
                impl Drop for Alive {
                    fn drop(&mut self) {
                        if let Some(ledger) = self.ledger.upgrade() {
                            ledger.serialization.failed.store(true, Ordering::SeqCst);
                        }
                        self.alive.store(false, Ordering::SeqCst);
                    }
                }
                let _alive = Alive {
                    alive: worker_alive,
                    ledger,
                };
                while let Ok(operation) = receiver.recv() {
                    operation.run();
                    #[cfg(test)]
                    if _alive.ledger.upgrade().is_some_and(|ledger| {
                        ledger
                            .serialization
                            .test_panic_after_operation
                            .swap(false, Ordering::SeqCst)
                    }) {
                        panic!("synthetic idle worker panic");
                    }
                }
            })
            .map_err(|_| ErrorCode::Storage)?;
        Ok(Self {
            sender,
            settlements: Arc::new(Semaphore::new(GUARDED_SETTLEMENTS)),
            controls: Arc::new(Semaphore::new(SERIALIZED_CONTROLS)),
            alive,
        })
    }

    fn settlement_permit(&self, ledger: &Ledger) -> Result<OwnedSemaphorePermit> {
        if ledger.serialization.failed.load(Ordering::SeqCst) || !self.alive.load(Ordering::SeqCst)
        {
            return Err(ErrorCode::Storage);
        }
        let permit = Arc::clone(&self.settlements).try_acquire_owned();
        if ledger.serialization.failed.load(Ordering::SeqCst) || !self.alive.load(Ordering::SeqCst)
        {
            return Err(ErrorCode::Storage);
        }
        permit.map_err(|_| ErrorCode::Capacity)
    }

    fn enqueue(&self, ledger: &Arc<Ledger>, action: SerializedAction) -> Result<()> {
        // Publish priority before the worker waits for the connection. Ordinary
        // guarded readers may not repeatedly overtake an already queued write.
        let operation = SerializedOperation {
            ledger: Arc::clone(ledger),
            action,
            pending: true,
        };
        ledger.serialization.pending.fetch_add(1, Ordering::SeqCst);
        // A failed send drops the operation just like an abandoned queued item.
        self.sender.send(operation).map_err(|_| ErrorCode::Storage)
    }
}

#[derive(Clone, Copy)]
struct Receipt {
    id: Uuid,
    owner: u32,
    job: Uuid,
    charge: Charge,
}

struct SerializedOperation {
    ledger: Arc<Ledger>,
    action: SerializedAction,
    pending: bool,
}

enum SerializedAction {
    Settle {
        receipt: Receipt,
        bytes: Option<u64>,
        cost: Option<u64>,
        completed: Option<oneshot::Sender<Result<()>>>,
        _permit: OwnedSemaphorePermit,
    },
    End {
        owner: u32,
        id: Uuid,
        state: JobState,
        completed: Option<oneshot::Sender<Result<Job>>>,
        _permit: OwnedSemaphorePermit,
    },
    Flush {
        completed: Option<oneshot::Sender<Result<()>>>,
        _permit: OwnedSemaphorePermit,
    },
}

impl SerializedOperation {
    fn complete(ledger: &Ledger, pending: &mut bool) {
        *pending = false;
        ledger.serialization.pending.fetch_sub(1, Ordering::SeqCst);
    }

    fn run(mut self) {
        let Self {
            ledger,
            action,
            pending,
        } = &mut self;
        match action {
            SerializedAction::Settle {
                receipt,
                bytes,
                cost,
                completed,
                ..
            } => {
                #[cfg(test)]
                let test_panic = ledger
                    .serialization
                    .test_panic_settlement
                    .lock()
                    .unwrap()
                    .take();
                #[cfg(test)]
                if let Some((started, resume)) = test_panic {
                    let _ = started.send(());
                    let _ = resume.recv();
                    panic!("synthetic settlement worker panic");
                }
                let result = ledger.settle(receipt, *bytes, *cost, true);
                if !matches!(result, Ok(()) | Err(ErrorCode::BudgetExceeded)) {
                    ledger.serialization.failed.store(true, Ordering::SeqCst);
                }
                Self::complete(ledger, pending);
                if let Some(completed) = completed.take() {
                    let _ = completed.send(result);
                }
            }
            SerializedAction::End {
                owner,
                id,
                state,
                completed,
                ..
            } => {
                let result = if ledger.serialization.failed.load(Ordering::SeqCst) {
                    Err(ErrorCode::Storage)
                } else {
                    ledger.end_inner(*owner, *id, *state, true)
                };
                if result.as_ref().err() == Some(&ErrorCode::Storage) {
                    ledger.serialization.failed.store(true, Ordering::SeqCst);
                }
                Self::complete(ledger, pending);
                if let Some(completed) = completed.take() {
                    let _ = completed.send(result);
                }
            }
            SerializedAction::Flush { completed, .. } => {
                let result = ledger.lock_for(true).map(|_| ()).and_then(|()| {
                    if ledger.serialization.failed.load(Ordering::SeqCst) {
                        Err(ErrorCode::Storage)
                    } else {
                        Ok(())
                    }
                });
                Self::complete(ledger, pending);
                if let Some(completed) = completed.take() {
                    let _ = completed.send(result);
                }
            }
        }
    }
}

impl Drop for SerializedOperation {
    fn drop(&mut self) {
        if self.pending {
            // Runs before responder/permit destruction, whether this item was
            // running, queued, or returned by a send racing worker shutdown.
            self.ledger
                .serialization
                .failed
                .store(true, Ordering::SeqCst);
            self.ledger
                .serialization
                .pending
                .fetch_sub(1, Ordering::SeqCst);
        }
    }
}

pub struct Ledger {
    connection: Mutex<Connection>,
    operator: Limits,
    guard: Option<guard::GuardedFiles>,
    serialization: Serialization,
}

impl Ledger {
    pub fn open(path: &Path, operator: Limits) -> Result<Arc<Self>> {
        operator.validate()?;
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| ErrorCode::Storage)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ErrorCode::Storage)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS jobs (
               id TEXT PRIMARY KEY, owner INTEGER NOT NULL, state TEXT NOT NULL,
               created_at INTEGER NOT NULL, deadline_at INTEGER NOT NULL,
               limits_json TEXT NOT NULL, usage_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS attempts (
               id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
               day TEXT NOT NULL, reserved_bytes INTEGER NOT NULL,
               reserved_cost INTEGER NOT NULL, actual_cost INTEGER,
               state TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS attempts_day ON attempts(day);
             CREATE INDEX IF NOT EXISTS attempts_job ON attempts(job_id);",
            )
            .map_err(|_| ErrorCode::Storage)?;
        Ok(Arc::new(Self {
            connection: Mutex::new(connection),
            operator,
            guard: None,
            serialization: Serialization::new(),
        }))
    }

    fn guarded(&self) -> bool {
        if self.guard.is_some() {
            return true;
        }
        #[cfg(test)]
        if self.serialization.test_guarded.load(Ordering::SeqCst) {
            return true;
        }
        false
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.lock_for(false)
    }

    fn lock_for(&self, serialized: bool) -> Result<MutexGuard<'_, Connection>> {
        if self.serialization.broken.load(Ordering::SeqCst)
            || (self.guarded() && !serialized && self.serialization.failed.load(Ordering::SeqCst))
        {
            return Err(ErrorCode::Storage);
        }
        // The isolated worker may wait. Ordinary guarded readers and admissions
        // fail promptly rather than blocking a Tokio worker or overtaking it.
        let connection = if self.guarded() && !serialized {
            if self.serialization.pending.load(Ordering::SeqCst) != 0 {
                return Err(ErrorCode::Capacity);
            }
            let connection = self.connection.try_lock().map_err(|error| match error {
                TryLockError::WouldBlock => ErrorCode::Capacity,
                TryLockError::Poisoned(_) => ErrorCode::Storage,
            })?;
            if self.serialization.pending.load(Ordering::SeqCst) != 0 {
                return Err(ErrorCode::Capacity);
            }
            connection
        } else {
            self.connection.lock().map_err(|_| ErrorCode::Storage)?
        };
        if self.serialization.broken.load(Ordering::SeqCst)
            || (self.guarded() && !serialized && self.serialization.failed.load(Ordering::SeqCst))
        {
            return Err(ErrorCode::Storage);
        }
        if let Some(guard) = &self.guard {
            guard.ensure_database(&connection)?;
        }
        Ok(connection)
    }

    fn prepare_commit(&self, connection: &Connection, now: i64) -> Result<Option<(i64, i64)>> {
        self.guard
            .as_ref()
            .map(|guard| guard.advance(connection, now))
            .transpose()
    }

    fn sync_write(&self, connection: &Connection, generation: Option<(i64, i64)>) -> Result<()> {
        let result = match (&self.guard, generation) {
            (Some(guard), Some(generation)) => guard
                .sync_write(generation)
                .and_then(|()| guard.ensure_database(connection)),
            (None, None) => Ok(()),
            _ => Err(ErrorCode::Storage),
        };
        // The SQLite commit already happened; never admit more work after an
        // ambiguous guarded commit, even if the witness subsequently recovers.
        if self.guard.is_some() && result.is_err() {
            self.serialization.broken.store(true, Ordering::SeqCst);
        }
        result
    }

    fn commit_error(&self) -> ErrorCode {
        if self.guard.is_some() {
            self.serialization.broken.store(true, Ordering::SeqCst);
        }
        ErrorCode::Storage
    }

    fn check_clock(&self, connection: &Connection, now: i64) -> Result<()> {
        if let Some(guard) = &self.guard {
            guard.check_clock(connection, now)?;
        }
        Ok(())
    }

    /// Called once after acquiring the service's exclusive instance lock.
    /// It is deliberately not a side effect of opening another DB connection.
    pub fn recover(&self) -> Result<()> {
        self.recover_at(Utc::now().timestamp())
    }

    fn recover_at(&self, now: i64) -> Result<()> {
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        self.check_clock(&tx, now)?;
        let active = {
            let mut statement = tx.prepare("SELECT id, usage_json FROM jobs WHERE state='active' OR id IN (SELECT job_id FROM attempts WHERE state='reserved')").map_err(|_| ErrorCode::Storage)?;
            statement
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|_| ErrorCode::Storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| ErrorCode::Storage)?
        };
        for (id, usage) in active {
            let mut usage: Usage = serde_json::from_str(&usage).map_err(|_| ErrorCode::Storage)?;
            usage.used_bytes = usage.used_bytes.saturating_add(usage.reserved_bytes);
            usage.reserved_bytes = 0;
            tx.execute("UPDATE jobs SET state=CASE WHEN state='active' THEN 'interrupted' ELSE state END, usage_json=?2 WHERE id=?1", params![id, encode(&usage)?])
                .map_err(|_| ErrorCode::Storage)?;
        }
        tx.execute(
            "UPDATE attempts SET state='unknown' WHERE state='reserved'",
            [],
        )
        .map_err(|_| ErrorCode::Storage)?;
        let generation = self.prepare_commit(&tx, now)?;
        tx.commit().map_err(|_| self.commit_error())?;
        self.sync_write(&connection, generation)
    }

    pub fn start(&self, owner: u32, requested: RequestedLimits) -> Result<Job> {
        let limits = requested.resolve(&self.operator)?;
        let now = Utc::now().timestamp();
        let job = Job {
            id: Uuid::new_v4(),
            state: JobState::Active,
            created_at: now,
            deadline_at: now + limits.seconds as i64,
            limits,
            usage: Usage::default(),
        };
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        self.check_clock(&tx, now)?;
        let count: usize = tx
            .query_row(
                "SELECT count(*) FROM jobs WHERE state='active' AND deadline_at>?1",
                [now],
                |row| row.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        if count >= self.operator.active_jobs {
            return Err(ErrorCode::Capacity);
        }
        tx.execute(
            "INSERT INTO jobs VALUES (?1,?2,'active',?3,?4,?5,?6)",
            params![
                job.id.to_string(),
                owner,
                now,
                job.deadline_at,
                encode(&job.limits)?,
                encode(&job.usage)?
            ],
        )
        .map_err(|_| ErrorCode::Storage)?;
        let generation = self.prepare_commit(&tx, now)?;
        tx.commit().map_err(|_| self.commit_error())?;
        self.sync_write(&connection, generation)?;
        Ok(job)
    }

    pub fn get(&self, owner: u32, id: Uuid) -> Result<Job> {
        let connection = self.lock()?;
        Self::read_job(&connection, owner, id)
    }

    fn read_job(connection: &Connection, owner: u32, id: Uuid) -> Result<Job> {
        let row = connection.query_row(
            "SELECT state,created_at,deadline_at,limits_json,usage_json FROM jobs WHERE id=?1 AND owner=?2",
            params![id.to_string(), owner], |row| Ok((
                row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?, row.get::<_, String>(4)?,
            )),
        ).optional().map_err(|_| ErrorCode::Storage)?.ok_or(ErrorCode::NotFound)?;
        let mut state: JobState = serde_json::from_value(serde_json::Value::String(row.0))
            .map_err(|_| ErrorCode::Storage)?;
        if state == JobState::Active && row.2 <= Utc::now().timestamp() {
            state = JobState::Expired;
        }
        Ok(Job {
            id,
            state,
            created_at: row.1,
            deadline_at: row.2,
            limits: serde_json::from_str(&row.3).map_err(|_| ErrorCode::Storage)?,
            usage: serde_json::from_str(&row.4).map_err(|_| ErrorCode::Storage)?,
        })
    }

    pub fn end(&self, owner: u32, id: Uuid, state: JobState) -> Result<Job> {
        self.end_inner(owner, id, state, false)
    }

    fn end_inner(&self, owner: u32, id: Uuid, state: JobState, serialized: bool) -> Result<Job> {
        if !matches!(
            state,
            JobState::Completed | JobState::Cancelled | JobState::Interrupted | JobState::Expired
        ) {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut connection = self.lock_for(serialized)?;
        if serialized && self.serialization.failed.load(Ordering::SeqCst) {
            return Err(ErrorCode::Storage);
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        let now = Utc::now().timestamp();
        self.check_clock(&tx, now)?;
        Self::read_job(&tx, owner, id)?;
        tx.execute(
            "UPDATE jobs SET state=?3 WHERE id=?1 AND owner=?2 AND state='active'",
            params![id.to_string(), owner, state.as_str()],
        )
        .map_err(|_| ErrorCode::Storage)?;
        let generation = self.prepare_commit(&tx, now)?;
        tx.commit().map_err(|_| self.commit_error())?;
        self.sync_write(&connection, generation)?;
        Self::read_job(&connection, owner, id)
    }

    /// In guarded mode, close after earlier queued settlements. Once enqueued,
    /// the operation continues even if the caller stops awaiting its result.
    pub async fn end_serialized(
        self: &Arc<Self>,
        owner: u32,
        id: Uuid,
        state: JobState,
    ) -> Result<Job> {
        if !self.guarded() {
            return self.end(owner, id, state);
        }
        let worker = self.serialization.worker(self)?;
        let permit = Arc::clone(&worker.controls)
            .acquire_owned()
            .await
            .map_err(|_| ErrorCode::Storage)?;
        let (completed, result) = oneshot::channel();
        worker.enqueue(
            self,
            SerializedAction::End {
                owner,
                id,
                state,
                completed: Some(completed),
                _permit: permit,
            },
        )?;
        result.await.map_err(|_| ErrorCode::Storage)?
    }

    /// In guarded mode, wait for earlier queued operations and report any
    /// settlement failure, including failures from a dropped reservation.
    pub async fn flush_serialized(self: &Arc<Self>) -> Result<()> {
        if !self.guarded() {
            return Ok(());
        }
        let worker = self.serialization.worker(self)?;
        let permit = Arc::clone(&worker.controls)
            .acquire_owned()
            .await
            .map_err(|_| ErrorCode::Storage)?;
        let (completed, result) = oneshot::channel();
        worker.enqueue(
            self,
            SerializedAction::Flush {
                completed: Some(completed),
                _permit: permit,
            },
        )?;
        result.await.map_err(|_| ErrorCode::Storage)?
    }

    pub fn reserve(self: &Arc<Self>, owner: u32, id: Uuid, charge: Charge) -> Result<Reservation> {
        self.reserve_inner(owner, id, charge, None, None)
    }

    /// Reserve up to the requested byte ceiling, atomically clamping it to the
    /// job's remaining capacity. All other resource reservations remain exact.
    /// `minimum` includes outgoing bytes and the response overflow sentinel.
    pub fn reserve_up_to_bytes(
        self: &Arc<Self>,
        owner: u32,
        id: Uuid,
        charge: Charge,
        minimum: u64,
    ) -> Result<Reservation> {
        if minimum == 0 || minimum > charge.bytes {
            return Err(ErrorCode::InvalidRequest);
        }
        self.reserve_inner(owner, id, charge, Some(minimum), None)
    }

    fn reserve_inner(
        self: &Arc<Self>,
        owner: u32,
        id: Uuid,
        mut charge: Charge,
        minimum: Option<u64>,
        clock: Option<chrono::DateTime<Utc>>,
    ) -> Result<Reservation> {
        let permit = if self.guarded() {
            Some(self.serialization.worker(self)?.settlement_permit(self)?)
        } else {
            None
        };
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        let mut job = Self::read_job(&tx, owner, id)?;
        if job.state != JobState::Active {
            return Err(ErrorCode::JobClosed);
        }
        let used = &mut job.usage;
        let cap = &job.limits;
        if let Some(minimum) = minimum {
            let available = cap
                .bytes
                .saturating_sub(used.used_bytes)
                .saturating_sub(used.reserved_bytes);
            charge.bytes = charge.bytes.min(available);
            if charge.bytes < minimum {
                return Err(ErrorCode::BudgetExceeded);
            }
        }
        let now = clock.unwrap_or_else(Utc::now);
        self.check_clock(&tx, now.timestamp())?;
        let day = now.format("%Y-%m-%d").to_string();
        // Unknown costs remain held across date boundaries in guarded mode.
        let daily_query = if self.guard.is_some() {
            "SELECT coalesce(sum(coalesce(actual_cost,reserved_cost)),0) FROM attempts WHERE day=?1 OR actual_cost IS NULL"
        } else {
            "SELECT coalesce(sum(coalesce(actual_cost,reserved_cost)),0) FROM attempts WHERE day=?1"
        };
        let daily: u64 = tx
            .query_row(daily_query, [&day], |row| row.get(0))
            .map_err(|_| ErrorCode::Storage)?;
        if !fits(
            used.used_bytes,
            used.reserved_bytes,
            charge.bytes,
            cap.bytes,
        ) || !fits(
            used.known_micro_usd,
            used.held_micro_usd,
            charge.micro_usd,
            cap.micro_usd,
        ) || !fits(daily, 0, charge.micro_usd, self.operator.daily_micro_usd)
            || !fits(
                used.requests.into(),
                0,
                charge.requests.into(),
                cap.requests.into(),
            )
            || !fits(
                used.queries.into(),
                0,
                charge.queries.into(),
                cap.queries.into(),
            )
            || !fits(
                used.documents.into(),
                0,
                charge.documents.into(),
                cap.documents.into(),
            )
            || !fits(
                used.pdf_pages.into(),
                0,
                charge.pdf_pages.into(),
                cap.pdf_pages.into(),
            )
            || !fits(
                used.browser_actions.into(),
                0,
                charge.browser_actions.into(),
                cap.browser_actions.into(),
            )
        {
            return Err(ErrorCode::BudgetExceeded);
        }
        used.reserved_bytes += charge.bytes;
        used.held_micro_usd += charge.micro_usd;
        used.requests += charge.requests;
        used.queries += charge.queries;
        used.documents += charge.documents;
        used.pdf_pages += charge.pdf_pages;
        used.browser_actions += charge.browser_actions;
        let reservation_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO attempts VALUES (?1,?2,?3,?4,?5,NULL,'reserved')",
            params![
                reservation_id.to_string(),
                id.to_string(),
                day,
                charge.bytes,
                charge.micro_usd
            ],
        )
        .map_err(|_| ErrorCode::Storage)?;
        tx.execute(
            "UPDATE jobs SET usage_json=?2 WHERE id=?1",
            params![id.to_string(), encode(used)?],
        )
        .map_err(|_| ErrorCode::Storage)?;
        let generation = self.prepare_commit(&tx, now.timestamp())?;
        tx.commit().map_err(|_| self.commit_error())?;
        self.sync_write(&connection, generation)?;
        Ok(Reservation {
            ledger: Arc::clone(self),
            receipt: Receipt {
                id: reservation_id,
                owner,
                job: id,
                charge,
            },
            permit,
            settled: false,
            known_cost: None,
            known_bytes: None,
        })
    }

    fn settle(
        &self,
        reservation: &Receipt,
        actual_bytes: Option<u64>,
        actual_cost: Option<u64>,
        serialized: bool,
    ) -> Result<()> {
        // Values outside the representable/reporting bound leave the reservation
        // held. A provider cannot overflow accounting or claim a negative charge.
        if actual_bytes.is_some_and(|n| n > 4096 * crate::config::MIB)
            || actual_cost.is_some_and(|n| n > 1_000_000_000_000)
        {
            return Err(ErrorCode::InvalidResponse);
        }
        let mut connection = self.lock_for(serialized)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
        let now = Utc::now().timestamp();
        self.check_clock(&tx, now)?;
        let state: String = tx
            .query_row(
                "SELECT state FROM attempts WHERE id=?1",
                [reservation.id.to_string()],
                |row| row.get(0),
            )
            .map_err(|_| ErrorCode::Storage)?;
        if state != "reserved" {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut job = Self::read_job(&tx, reservation.owner, reservation.job)?;
        let bytes = actual_bytes.unwrap_or(reservation.charge.bytes);
        job.usage.reserved_bytes = job
            .usage
            .reserved_bytes
            .checked_sub(reservation.charge.bytes)
            .ok_or(ErrorCode::Storage)?;
        job.usage.used_bytes = job
            .usage
            .used_bytes
            .checked_add(bytes)
            .ok_or(ErrorCode::Storage)?;
        if let Some(cost) = actual_cost {
            job.usage.held_micro_usd = job
                .usage
                .held_micro_usd
                .checked_sub(reservation.charge.micro_usd)
                .ok_or(ErrorCode::Storage)?;
            job.usage.known_micro_usd = job
                .usage
                .known_micro_usd
                .checked_add(cost)
                .ok_or(ErrorCode::Storage)?;
        }
        let exceeded = bytes > reservation.charge.bytes
            || actual_cost.is_some_and(|cost| cost > reservation.charge.micro_usd);
        if exceeded {
            job.state = JobState::Exhausted;
        }
        tx.execute(
            "UPDATE attempts SET actual_cost=?2,state=?3 WHERE id=?1",
            params![
                reservation.id.to_string(),
                actual_cost,
                if actual_cost.is_some() {
                    "settled"
                } else {
                    "unknown"
                }
            ],
        )
        .map_err(|_| ErrorCode::Storage)?;
        tx.execute(
            "UPDATE jobs SET usage_json=?2,state=?3 WHERE id=?1",
            params![job.id.to_string(), encode(&job.usage)?, job.state.as_str()],
        )
        .map_err(|_| ErrorCode::Storage)?;
        let generation = self.prepare_commit(&tx, now)?;
        tx.commit().map_err(|_| self.commit_error())?;
        self.sync_write(&connection, generation)?;
        if exceeded {
            Err(ErrorCode::BudgetExceeded)
        } else {
            Ok(())
        }
    }
}

fn fits(used: u64, reserved: u64, additional: u64, limit: u64) -> bool {
    used.checked_add(reserved)
        .and_then(|total| total.checked_add(additional))
        .is_some_and(|total| total <= limit)
}

fn encode(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|_| ErrorCode::Storage)
}

pub struct Reservation {
    ledger: Arc<Ledger>,
    receipt: Receipt,
    permit: Option<OwnedSemaphorePermit>,
    settled: bool,
    known_cost: Option<u64>,
    known_bytes: Option<u64>,
}

impl Reservation {
    pub fn reserved_bytes(&self) -> u64 {
        self.receipt.charge.bytes
    }
    /// A received status can establish billing even when its body later stalls.
    /// A crash before settlement still conservatively retains the durable hold.
    pub fn remember_cost(&mut self, cost: Option<u64>) {
        self.known_cost = cost.or(self.known_cost);
    }

    fn enqueue_settlement(
        &mut self,
        bytes: Option<u64>,
        cost: Option<u64>,
        completed: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        let permit = self.permit.take().ok_or(ErrorCode::Storage)?;
        // The operation owns the receipt and permit from this point. A failed
        // send leaves the previously committed reservation held and is sticky.
        self.settled = true;
        let ledger = &self.ledger;
        let worker = ledger.serialization.worker(ledger)?;
        worker.enqueue(
            ledger,
            SerializedAction::Settle {
                receipt: self.receipt,
                bytes,
                cost,
                completed,
                _permit: permit,
            },
        )
    }

    pub fn finish(mut self, bytes: u64, micro_usd: Option<u64>) -> Result<()> {
        self.remember_cost(micro_usd);
        self.known_bytes = Some(bytes);
        let result = self
            .ledger
            .settle(&self.receipt, Some(bytes), self.known_cost, false);
        if result.is_ok() || result == Err(ErrorCode::BudgetExceeded) {
            self.settled = true;
        } else if self.ledger.guarded() && result != Err(ErrorCode::Capacity) {
            // A storage/validation failure may be ambiguous after a commit. Do
            // not race another synchronous fixture or retry a possible commit.
            self.ledger
                .serialization
                .failed
                .store(true, Ordering::SeqCst);
            self.settled = true;
        }
        result
    }

    /// Queue a guarded receipt immediately, even if the returned future is
    /// dropped unpolled. Unguarded settlement retains its synchronous behavior.
    pub fn finish_serialized(
        mut self,
        bytes: u64,
        micro_usd: Option<u64>,
    ) -> impl Future<Output = Result<()>> + Send {
        let completion = if self.ledger.guarded() {
            self.remember_cost(micro_usd);
            let (completed, result) = oneshot::channel();
            self.enqueue_settlement(Some(bytes), self.known_cost, Some(completed))
                .map(|()| Some(result))
        } else {
            self.finish(bytes, micro_usd).map(|()| None)
        };
        async move {
            match completion? {
                Some(result) => result.await.map_err(|_| ErrorCode::Storage)?,
                None => Ok(()),
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if self.ledger.guarded() {
            let _ = self.enqueue_settlement(self.known_bytes, self.known_cost, None);
        } else {
            // Preserve the original synchronous destructor in default mode.
            let _ = self
                .ledger
                .settle(&self.receipt, None, self.known_cost, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn ledger(root: &tempfile::TempDir, limits: Limits) -> Arc<Ledger> {
        Ledger::open(&root.path().join("ledger.sqlite"), limits).unwrap()
    }

    #[tokio::test]
    async fn unguarded_accounting_remains_immediate_without_a_worker() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 10,
                    micro_usd: 100,
                    ..Charge::default()
                },
            )
            .unwrap();
        assert!(ledger.serialization.worker.get().is_none());
        let completed = reservation.finish_serialized(3, Some(20));
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!((usage.used_bytes, usage.known_micro_usd), (3, 20));
        completed.await.unwrap();
        let unknown = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 5,
                    micro_usd: 10,
                    ..Charge::default()
                },
            )
            .unwrap();
        drop(unknown);
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!((usage.used_bytes, usage.reserved_bytes), (8, 0));
        assert_eq!(usage.held_micro_usd, 10);
        ledger.flush_serialized().await.unwrap();
        assert_eq!(
            ledger
                .end_serialized(1001, job.id, JobState::Cancelled)
                .await
                .unwrap()
                .state,
            JobState::Cancelled
        );
        assert!(ledger.serialization.worker.get().is_none());
    }

    fn hold_connection(ledger: &Arc<Ledger>) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (ready, wait_ready) = mpsc::channel();
        let (release, wait_release) = mpsc::channel();
        let ledger = Arc::clone(ledger);
        let thread = std::thread::spawn(move || {
            let _connection = ledger.connection.lock().unwrap();
            ready.send(()).unwrap();
            let _ = wait_release.recv();
        });
        wait_ready.recv().unwrap();
        (release, thread)
    }

    fn simulate_guard(ledger: &Ledger) {
        ledger
            .serialization
            .test_guarded
            .store(true, Ordering::SeqCst);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_receipts_survive_contention_and_cancelled_waiters() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let charge = Charge {
            bytes: 10,
            micro_usd: 100,
            ..Charge::default()
        };
        let first = ledger.reserve(1001, job.id, charge).unwrap();
        let mut known = ledger.reserve(1001, job.id, charge).unwrap();
        let unknown = ledger.reserve(1001, job.id, charge).unwrap();
        let last = ledger.reserve(1001, job.id, charge).unwrap();
        known.remember_cost(Some(40));
        let (release, holder) = hold_connection(&ledger);

        // Dropping an unpolled settlement future must not discard its receipt.
        drop(first.finish_serialized(7, Some(80)));
        drop(known);
        drop(unknown);
        let waiter = tokio::spawn(last.finish_serialized(3, Some(70)));
        assert_eq!(ledger.get(1001, job.id).err(), Some(ErrorCode::Capacity));
        let reader = Arc::clone(&ledger);
        let progress = tokio::spawn(async move {
            tokio::task::yield_now().await;
            reader.get(1001, job.id).err()
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), progress)
                .await
                .unwrap()
                .unwrap(),
            Some(ErrorCode::Capacity)
        );
        assert!(!waiter.is_finished());
        release.send(()).unwrap();
        holder.join().unwrap();
        waiter.await.unwrap().unwrap();
        ledger.flush_serialized().await.unwrap();
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!((usage.used_bytes, usage.reserved_bytes), (30, 0));
        assert_eq!((usage.known_micro_usd, usage.held_micro_usd), (190, 100));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_close_survives_a_cancelled_caller() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let id = ledger.start(1001, RequestedLimits::default()).unwrap().id;
        simulate_guard(&ledger);
        let (release, holder) = hold_connection(&ledger);
        let closing = Arc::clone(&ledger);
        let task =
            tokio::spawn(
                async move { closing.end_serialized(1001, id, JobState::Cancelled).await },
            );
        tokio::time::timeout(Duration::from_secs(1), async {
            while ledger.serialization.pending.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        release.send(()).unwrap();
        holder.join().unwrap();
        ledger.flush_serialized().await.unwrap();
        assert_eq!(ledger.get(1001, id).unwrap().state, JobState::Cancelled);
    }

    #[test]
    fn guarded_admission_requires_a_settlement_slot() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let worker = ledger.serialization.worker(&ledger).unwrap();
        let slots = Arc::clone(&worker.settlements)
            .try_acquire_many_owned(GUARDED_SETTLEMENTS as u32)
            .unwrap();
        assert!(matches!(
            ledger.reserve(
                1001,
                job.id,
                Charge {
                    micro_usd: 100,
                    ..Charge::default()
                }
            ),
            Err(ErrorCode::Capacity)
        ));
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.held_micro_usd, 0);
        drop(slots);
    }

    #[tokio::test]
    async fn settlement_failure_is_sticky_and_keeps_the_durable_hold() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 10,
                    micro_usd: 100,
                    ..Charge::default()
                },
            )
            .unwrap();
        assert_eq!(
            reservation
                .finish_serialized(1, Some(1_000_000_000_001))
                .await,
            Err(ErrorCode::InvalidResponse)
        );
        assert_eq!(ledger.flush_serialized().await, Err(ErrorCode::Storage));
        let worker = ledger.serialization.worker(&ledger).unwrap();
        let slots = Arc::clone(&worker.settlements)
            .acquire_many_owned(GUARDED_SETTLEMENTS as u32)
            .await
            .unwrap();
        assert!(matches!(
            ledger.reserve(1001, job.id, Charge::default()),
            Err(ErrorCode::Storage)
        ));
        drop(slots);
        let connection = ledger.lock_for(true).unwrap();
        let usage = Ledger::read_job(&connection, 1001, job.id).unwrap().usage;
        assert_eq!((usage.reserved_bytes, usage.held_micro_usd), (10, 100));
    }

    #[tokio::test]
    async fn queued_close_refuses_a_settlement_failure_after_a_barrier() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        ledger.flush_serialized().await.unwrap();
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    micro_usd: 100,
                    ..Charge::default()
                },
            )
            .unwrap();
        let settlement = reservation.finish_serialized(0, Some(1_000_000_000_001));
        assert!(matches!(
            ledger
                .end_serialized(1001, job.id, JobState::Cancelled)
                .await,
            Err(ErrorCode::Storage)
        ));
        assert_eq!(settlement.await, Err(ErrorCode::InvalidResponse));
        let connection = ledger.lock_for(true).unwrap();
        let job = Ledger::read_job(&connection, 1001, job.id).unwrap();
        assert_eq!(job.state, JobState::Active);
        assert_eq!(job.usage.held_micro_usd, 100);
    }

    #[tokio::test]
    async fn unavailable_worker_keeps_reservation_held_and_reports_failure() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let (sender, receiver) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        assert!(
            ledger
                .serialization
                .worker
                .set(Ok(SerializationWorker {
                    sender,
                    settlements: Arc::new(Semaphore::new(GUARDED_SETTLEMENTS)),
                    controls: Arc::new(Semaphore::new(SERIALIZED_CONTROLS)),
                    alive: Arc::clone(&alive),
                }))
                .is_ok()
        );
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 10,
                    micro_usd: 100,
                    ..Charge::default()
                },
            )
            .unwrap();
        drop(receiver);
        alive.store(false, Ordering::SeqCst);
        assert_eq!(
            reservation.finish_serialized(2, Some(100)).await,
            Err(ErrorCode::Storage)
        );
        assert_eq!(ledger.flush_serialized().await, Err(ErrorCode::Storage));
        assert!(matches!(
            ledger.reserve(1001, job.id, Charge::default()),
            Err(ErrorCode::Storage)
        ));
        let connection = ledger.lock_for(true).unwrap();
        let usage = Ledger::read_job(&connection, 1001, job.id).unwrap().usage;
        assert_eq!((usage.reserved_bytes, usage.held_micro_usd), (10, 100));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicked_worker_drains_running_and_queued_operations_without_releasing_holds() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let charge = Charge {
            bytes: 10,
            micro_usd: 100,
            ..Charge::default()
        };
        let running = ledger.reserve(1001, job.id, charge).unwrap();
        let queued = ledger.reserve(1001, job.id, charge).unwrap();
        let without_waiter = ledger.reserve(1001, job.id, charge).unwrap();

        let (started, wait_started) = mpsc::channel();
        let (resume, wait_resume) = mpsc::channel();
        *ledger.serialization.test_panic_settlement.lock().unwrap() = Some((started, wait_resume));
        let running_result = running.finish_serialized(1, Some(10));
        wait_started.recv_timeout(Duration::from_secs(3)).unwrap();
        let queued_result = queued.finish_serialized(2, Some(20));
        drop(without_waiter.finish_serialized(3, Some(30)));
        let closing_ledger = Arc::clone(&ledger);
        let closing = tokio::spawn(async move {
            closing_ledger
                .end_serialized(1001, job.id, JobState::Cancelled)
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while ledger.serialization.pending.load(Ordering::SeqCst) != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ledger.get(1001, job.id).err(), Some(ErrorCode::Capacity));

        resume.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), running_result)
                .await
                .unwrap(),
            Err(ErrorCode::Storage)
        );
        // The running responder cannot wake before the sticky failure is set.
        assert_eq!(ledger.get(1001, job.id).err(), Some(ErrorCode::Storage));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), queued_result)
                .await
                .unwrap(),
            Err(ErrorCode::Storage)
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), closing)
                .await
                .unwrap()
                .unwrap(),
            Err(ErrorCode::Storage)
        ));
        assert_eq!(ledger.serialization.pending.load(Ordering::SeqCst), 0);
        assert!(matches!(
            ledger.reserve(1001, job.id, Charge::default()),
            Err(ErrorCode::Storage)
        ));
        assert!(matches!(
            ledger.start(1001, RequestedLimits::default()),
            Err(ErrorCode::Storage)
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), ledger.flush_serialized())
                .await
                .unwrap(),
            Err(ErrorCode::Storage)
        );

        // Reopen before recovery to inspect the committed reservations, then
        // recover as after a process restart and keep all costs unknown.
        let reopened = Ledger::open(&root.path().join("ledger.sqlite"), Limits::default()).unwrap();
        let persisted = reopened.get(1001, job.id).unwrap();
        assert_eq!(persisted.state, JobState::Active);
        assert_eq!(
            (
                persisted.usage.reserved_bytes,
                persisted.usage.held_micro_usd,
                persisted.usage.known_micro_usd
            ),
            (30, 300, 0)
        );
        reopened.recover().unwrap();
        let recovered = reopened.get(1001, job.id).unwrap();
        assert_eq!(recovered.state, JobState::Interrupted);
        assert_eq!(
            (
                recovered.usage.used_bytes,
                recovered.usage.reserved_bytes,
                recovered.usage.held_micro_usd,
                recovered.usage.known_micro_usd
            ),
            (30, 0, 300, 0)
        );
    }

    #[tokio::test]
    async fn worker_exit_with_no_pending_operation_is_sticky() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let worker = ledger.serialization.worker(&ledger).unwrap();
        ledger
            .serialization
            .test_panic_after_operation
            .store(true, Ordering::SeqCst);
        assert_eq!(ledger.flush_serialized().await, Ok(()));
        tokio::time::timeout(Duration::from_secs(3), async {
            while worker.alive.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ledger.serialization.pending.load(Ordering::SeqCst), 0);
        assert_eq!(ledger.get(1001, job.id).err(), Some(ErrorCode::Storage));
        assert!(matches!(
            ledger.reserve(1001, job.id, Charge::default()),
            Err(ErrorCode::Storage)
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), ledger.flush_serialized())
                .await
                .unwrap(),
            Err(ErrorCode::Storage)
        );
    }

    #[tokio::test]
    async fn sends_during_and_after_worker_shutdown_reconcile_pending_and_keep_holds() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let (sender, receiver) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        assert!(
            ledger
                .serialization
                .worker
                .set(Ok(SerializationWorker {
                    sender,
                    settlements: Arc::new(Semaphore::new(GUARDED_SETTLEMENTS)),
                    controls: Arc::new(Semaphore::new(SERIALIZED_CONTROLS)),
                    alive: Arc::clone(&alive),
                }))
                .is_ok()
        );
        let charge = Charge {
            bytes: 10,
            micro_usd: 100,
            ..Charge::default()
        };
        let before = ledger.reserve(1001, job.id, charge).unwrap();
        let during = ledger.reserve(1001, job.id, charge).unwrap();
        let after = ledger.reserve(1001, job.id, charge).unwrap();
        let before_result = before.finish_serialized(1, Some(10));

        // The worker publishes failure before dropping its receiver. A send
        // in this interval can still succeed and must be reconciled on drop.
        ledger.serialization.failed.store(true, Ordering::SeqCst);
        alive.store(false, Ordering::SeqCst);
        let during_result = during.finish_serialized(2, Some(20));
        assert_eq!(ledger.serialization.pending.load(Ordering::SeqCst), 2);
        drop(receiver);
        assert_eq!(ledger.serialization.pending.load(Ordering::SeqCst), 0);
        assert_eq!(before_result.await, Err(ErrorCode::Storage));
        assert_eq!(during_result.await, Err(ErrorCode::Storage));

        // A send after the receiver is gone is reconciled by SendError.
        assert_eq!(
            after.finish_serialized(3, Some(30)).await,
            Err(ErrorCode::Storage)
        );
        assert_eq!(ledger.serialization.pending.load(Ordering::SeqCst), 0);
        let worker = ledger.serialization.worker(&ledger).unwrap();
        assert_eq!(worker.settlements.available_permits(), GUARDED_SETTLEMENTS);
        assert_eq!(ledger.get(1001, job.id).err(), Some(ErrorCode::Storage));
        assert!(matches!(
            ledger.reserve(1001, job.id, Charge::default()),
            Err(ErrorCode::Storage)
        ));
        let reopened = Ledger::open(&root.path().join("ledger.sqlite"), Limits::default()).unwrap();
        let persisted = reopened.get(1001, job.id).unwrap();
        assert_eq!(
            (
                persisted.usage.reserved_bytes,
                persisted.usage.held_micro_usd
            ),
            (30, 300)
        );
        reopened.recover().unwrap();
        assert_eq!(
            reopened.get(1001, job.id).unwrap().usage.held_micro_usd,
            300
        );
    }

    #[tokio::test]
    async fn serialized_overrun_is_recorded_without_poisoning_the_barrier() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        simulate_guard(&ledger);
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 10,
                    micro_usd: 10,
                    ..Charge::default()
                },
            )
            .unwrap();
        assert_eq!(
            reservation.finish_serialized(11, Some(20)).await,
            Err(ErrorCode::BudgetExceeded)
        );
        ledger.flush_serialized().await.unwrap();
        let job = ledger.get(1001, job.id).unwrap();
        assert_eq!(job.state, JobState::Exhausted);
        assert_eq!(
            (job.usage.known_micro_usd, job.usage.held_micro_usd),
            (20, 0)
        );
    }

    #[test]
    fn clients_cannot_raise_operator_limits() {
        let request = RequestedLimits {
            micro_usd: Some(500_001),
            ..RequestedLimits::default()
        };
        assert!(request.resolve(&Limits::default()).is_err());
        let request = RequestedLimits {
            micro_usd: Some(0),
            requests: Some(0),
            ..RequestedLimits::default()
        };
        assert_eq!(request.resolve(&Limits::default()).unwrap().micro_usd, 0);
    }

    #[test]
    fn remaining_capacity_includes_holds_and_actual_settlement() {
        let root = tempfile::tempdir().unwrap();
        let ledger = ledger(&root, Limits::default());
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let reservation = ledger
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 10,
                    micro_usd: 3000,
                    queries: 1,
                    requests: 1,
                    documents: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        let held = ledger.get(1001, job.id).unwrap().remaining();
        assert_eq!(held.bytes, job.limits.bytes - 10);
        assert_eq!(held.micro_usd, job.limits.micro_usd - 3000);
        assert_eq!(held.queries, job.limits.queries - 1);
        assert_eq!(held.requests, job.limits.requests - 1);
        assert_eq!(held.documents, job.limits.documents - 1);
        reservation.finish(4, Some(1000)).unwrap();
        let settled = ledger.get(1001, job.id).unwrap().remaining();
        assert_eq!(settled.bytes, job.limits.bytes - 4);
        assert_eq!(settled.micro_usd, job.limits.micro_usd - 1000);
        assert_eq!(settled.queries, held.queries);
    }

    #[test]
    fn clamped_parallel_reservations_share_one_atomic_byte_limit() {
        let root = tempfile::tempdir().unwrap();
        let first = ledger(&root, Limits::default());
        let second = ledger(&root, Limits::default());
        let job = first
            .start(
                1001,
                RequestedLimits {
                    bytes: Some(100),
                    ..Default::default()
                },
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first.clone(), second]
            .into_iter()
            .map(|ledger| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    ledger
                        .reserve_up_to_bytes(
                            1001,
                            job.id,
                            Charge {
                                bytes: 80,
                                requests: 1,
                                ..Default::default()
                            },
                            2,
                        )
                        .unwrap()
                })
            })
            .collect();
        let reservations: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            reservations
                .iter()
                .map(Reservation::reserved_bytes)
                .sum::<u64>(),
            100
        );
        assert_eq!(first.get(1001, job.id).unwrap().usage.reserved_bytes, 100);
        for reservation in reservations {
            reservation.finish(1, Some(0)).unwrap();
        }
        assert_eq!(first.get(1001, job.id).unwrap().usage.used_bytes, 2);
    }

    #[test]
    fn simultaneous_reservations_share_one_atomic_cap() {
        let root = tempfile::tempdir().unwrap();
        let store = ledger(&root, Limits::default());
        let job = store.start(1001, RequestedLimits::default()).unwrap();
        let barrier = Arc::new(Barrier::new(12));
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let store = Arc::clone(&store);
                    scope.spawn(move || {
                        barrier.wait();
                        store
                            .reserve(
                                1001,
                                job.id,
                                Charge {
                                    micro_usd: 100_000,
                                    requests: 1,
                                    ..Charge::default()
                                },
                            )
                            .is_ok()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.into_iter().filter(|accepted| *accepted).count(), 5);
        let summary = store.get(1001, job.id).unwrap();
        assert_eq!(summary.usage.held_micro_usd, 500_000);
        assert_eq!(summary.usage.requests, 5);
    }

    #[test]
    fn separate_database_connections_share_daily_cap() {
        let root = tempfile::tempdir().unwrap();
        let limits = Limits {
            daily_micro_usd: 500_000,
            ..Limits::default()
        };
        let first = ledger(&root, limits.clone());
        let second = ledger(&root, limits);
        let a = first.start(1001, RequestedLimits::default()).unwrap();
        let b = second.start(1002, RequestedLimits::default()).unwrap();
        let hold = first
            .reserve(
                1001,
                a.id,
                Charge {
                    micro_usd: 400_000,
                    ..Charge::default()
                },
            )
            .unwrap();
        assert!(
            second
                .reserve(
                    1002,
                    b.id,
                    Charge {
                        micro_usd: 200_000,
                        ..Charge::default()
                    }
                )
                .is_err()
        );
        hold.finish(0, Some(100_000)).unwrap();
        second
            .reserve(
                1002,
                b.id,
                Charge {
                    micro_usd: 400_000,
                    ..Charge::default()
                },
            )
            .unwrap();
    }

    #[test]
    fn crash_recovery_preserves_unknown_cost_and_closes_work() {
        let root = tempfile::tempdir().unwrap();
        let limits = Limits {
            daily_micro_usd: 500_000,
            ..Limits::default()
        };
        let store = ledger(&root, limits.clone());
        let job = store.start(1001, RequestedLimits::default()).unwrap();
        let hold = store
            .reserve(
                1001,
                job.id,
                Charge {
                    micro_usd: 500_000,
                    bytes: 100,
                    ..Charge::default()
                },
            )
            .unwrap();
        // A second process observes the durable reservation without running the
        // original reservation's destructor, as after SIGKILL.
        let restarted = ledger(&root, limits);
        restarted.recover().unwrap();
        let old = restarted.get(1001, job.id).unwrap();
        assert_eq!(old.state, JobState::Interrupted);
        assert_eq!(old.usage.held_micro_usd, 500_000);
        assert_eq!((old.usage.used_bytes, old.usage.reserved_bytes), (100, 0));
        let new = restarted.start(1001, RequestedLimits::default()).unwrap();
        assert!(
            restarted
                .reserve(
                    1001,
                    new.id,
                    Charge {
                        micro_usd: 1,
                        ..Charge::default()
                    }
                )
                .is_err()
        );
        drop(hold);
        assert_eq!(
            restarted.get(1001, job.id).unwrap().usage.held_micro_usd,
            500_000
        );
    }

    #[test]
    fn admission_checks_bytes_and_counts_before_spending() {
        let root = tempfile::tempdir().unwrap();
        let store = ledger(&root, Limits::default());
        let job = store
            .start(
                1001,
                RequestedLimits {
                    bytes: Some(100),
                    requests: Some(1),
                    ..RequestedLimits::default()
                },
            )
            .unwrap();
        let first = store
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 80,
                    requests: 1,
                    ..Charge::default()
                },
            )
            .unwrap();
        assert!(
            store
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        bytes: 21,
                        ..Charge::default()
                    }
                )
                .is_err()
        );
        first.finish(5, Some(0)).unwrap();
        assert!(
            store
                .reserve(
                    1001,
                    job.id,
                    Charge {
                        requests: 1,
                        ..Charge::default()
                    }
                )
                .is_err()
        );
        assert_eq!(store.get(1001, job.id).unwrap().usage.used_bytes, 5);
    }

    #[test]
    fn recovery_settles_bytes_for_already_cancelled_jobs() {
        let root = tempfile::tempdir().unwrap();
        let store = ledger(&root, Limits::default());
        let job = store.start(1001, RequestedLimits::default()).unwrap();
        let hold = store
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 100,
                    micro_usd: 5000,
                    ..Charge::default()
                },
            )
            .unwrap();
        store.end(1001, job.id, JobState::Cancelled).unwrap();
        let restarted = ledger(&root, Limits::default());
        restarted.recover().unwrap();
        let recovered = restarted.get(1001, job.id).unwrap();
        assert_eq!(recovered.state, JobState::Cancelled);
        assert_eq!(
            (recovered.usage.used_bytes, recovered.usage.reserved_bytes),
            (100, 0)
        );
        assert_eq!(recovered.usage.held_micro_usd, 5000);
        drop(hold);
    }

    #[test]
    fn wrong_owner_and_finished_jobs_cannot_reserve() {
        let root = tempfile::tempdir().unwrap();
        let store = ledger(&root, Limits::default());
        let job = store.start(1001, RequestedLimits::default()).unwrap();
        assert_eq!(store.get(1002, job.id).unwrap_err(), ErrorCode::NotFound);
        assert!(store.reserve(1002, job.id, Charge::default()).is_err());
        store.end(1001, job.id, JobState::Cancelled).unwrap();
        assert!(store.reserve(1001, job.id, Charge::default()).is_err());
    }

    #[test]
    fn overrun_is_recorded_and_exhausts_the_job() {
        let root = tempfile::tempdir().unwrap();
        let store = ledger(&root, Limits::default());
        let job = store.start(1001, RequestedLimits::default()).unwrap();
        let hold = store
            .reserve(
                1001,
                job.id,
                Charge {
                    bytes: 10,
                    micro_usd: 10,
                    ..Charge::default()
                },
            )
            .unwrap();
        assert_eq!(
            hold.finish(11, Some(20)).unwrap_err(),
            ErrorCode::BudgetExceeded
        );
        let result = store.get(1001, job.id).unwrap();
        assert_eq!(result.state, JobState::Exhausted);
        assert_eq!(result.usage.known_micro_usd, 20);
        assert_eq!(result.usage.held_micro_usd, 0);
    }
}
