//! Persistent admission control. Money is represented in integer micro-dollars.
//! A process crash never turns an uncertain external charge into free capacity.

use crate::config::Limits;
use crate::error::{ErrorCode, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use uuid::Uuid;

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

pub struct Ledger {
    connection: Mutex<Connection>,
    operator: Limits,
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
        }))
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| ErrorCode::Storage)
    }

    /// Called once after acquiring the service's exclusive instance lock.
    /// It is deliberately not a side effect of opening another DB connection.
    pub fn recover(&self) -> Result<()> {
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
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
        tx.commit().map_err(|_| ErrorCode::Storage)
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
        tx.commit().map_err(|_| ErrorCode::Storage)?;
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
        if !matches!(
            state,
            JobState::Completed | JobState::Cancelled | JobState::Interrupted | JobState::Expired
        ) {
            return Err(ErrorCode::InvalidRequest);
        }
        let connection = self.lock()?;
        Self::read_job(&connection, owner, id)?;
        connection
            .execute(
                "UPDATE jobs SET state=?3 WHERE id=?1 AND owner=?2 AND state='active'",
                params![id.to_string(), owner, state.as_str()],
            )
            .map_err(|_| ErrorCode::Storage)?;
        Self::read_job(&connection, owner, id)
    }

    pub fn reserve(self: &Arc<Self>, owner: u32, id: Uuid, charge: Charge) -> Result<Reservation> {
        self.reserve_inner(owner, id, charge, None)
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
        self.reserve_inner(owner, id, charge, Some(minimum))
    }

    fn reserve_inner(
        self: &Arc<Self>,
        owner: u32,
        id: Uuid,
        mut charge: Charge,
        minimum: Option<u64>,
    ) -> Result<Reservation> {
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
        let day = Utc::now().format("%Y-%m-%d").to_string();
        let daily: u64 = tx.query_row(
            "SELECT coalesce(sum(coalesce(actual_cost,reserved_cost)),0) FROM attempts WHERE day=?1",
            [&day], |row| row.get(0),
        ).map_err(|_| ErrorCode::Storage)?;
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
        tx.commit().map_err(|_| ErrorCode::Storage)?;
        Ok(Reservation {
            ledger: Arc::clone(self),
            id: reservation_id,
            owner,
            job: id,
            charge,
            settled: false,
            known_cost: None,
        })
    }

    fn settle(
        &self,
        reservation: &Reservation,
        actual_bytes: Option<u64>,
        actual_cost: Option<u64>,
    ) -> Result<()> {
        // Values outside the representable/reporting bound leave the reservation
        // held. A provider cannot overflow accounting or claim a negative charge.
        if actual_bytes.is_some_and(|n| n > 4096 * crate::config::MIB)
            || actual_cost.is_some_and(|n| n > 1_000_000_000_000)
        {
            return Err(ErrorCode::InvalidResponse);
        }
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ErrorCode::Storage)?;
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
        tx.commit().map_err(|_| ErrorCode::Storage)?;
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
    id: Uuid,
    owner: u32,
    job: Uuid,
    charge: Charge,
    settled: bool,
    known_cost: Option<u64>,
}

impl Reservation {
    pub fn reserved_bytes(&self) -> u64 {
        self.charge.bytes
    }
    /// A received status can establish billing even when its body later stalls.
    /// A crash before settlement still conservatively retains the durable hold.
    pub fn remember_cost(&mut self, cost: Option<u64>) {
        self.known_cost = cost;
    }
    pub fn finish(mut self, bytes: u64, micro_usd: Option<u64>) -> Result<()> {
        let result = self
            .ledger
            .settle(&self, Some(bytes), micro_usd.or(self.known_cost));
        if result.is_ok() || result == Err(ErrorCode::BudgetExceeded) {
            self.settled = true;
        }
        result
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.settled {
            // On DB errors the durable pre-IO reservation remains intact.
            let _ = self.ledger.settle(self, None, self.known_cost);
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
