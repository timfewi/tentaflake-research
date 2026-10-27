//! Job ownership, cooperative cancellation and the five tool implementations.
//! Cancellation always waits for the operation to release its worker/IO leases.

use crate::api::*;
use crate::archive::{Evidence, NewSource, RepresentationKind, SourceWarning};
use crate::browser::profile::Profile;
use crate::budget::{Charge, Job, JobState, Ledger, RequestedLimits};
use crate::cache::{Cache, Key};
use crate::config::{Capability, Config, Limits, Privacy};
use crate::egress::{EgressMode, EgressState};
use crate::error::{ErrorCode, Result};
use crate::fetch::{DiscoveryDecision, FetchRecord, Fetcher, Parser};
use crate::http::{BrowserRequest, HttpRequest, HttpResponse, Transport};
use crate::policy::{PublicUrl, sha256};
use crate::protocol::Tool;
use crate::provider::{
    Context, ScrapeProvider, SearchProvider, SearchQuery, SummarizeProvider, SummaryInput,
};
use crate::reports::Reports;
use crate::store::EvidenceStore;
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_CRAWL_PACING_ORIGINS: usize = 1024;

/// A provider can fall back only when every request in its attempt has a
/// settled fixed charge or is confirmed unbilled. An aborted request remains
/// uncertain even if the adapter no longer has a future to inspect.
struct ProviderAttempt<'a> {
    inner: &'a dyn Transport,
    uncertain: AtomicBool,
}

impl<'a> ProviderAttempt<'a> {
    fn new(inner: &'a dyn Transport) -> Self {
        Self {
            inner,
            uncertain: AtomicBool::new(false),
        }
    }

    fn fallback_safe(&self) -> bool {
        !self.uncertain.load(Ordering::SeqCst)
    }

    fn guard(&self, request: &HttpRequest) -> CostGuard<'_> {
        CostGuard {
            uncertain: &self.uncertain,
            may_have_cost: request.micro_usd != 0,
            errors_are_unbilled: request.errors_are_unbilled,
        }
    }
}

struct CostGuard<'a> {
    uncertain: &'a AtomicBool,
    may_have_cost: bool,
    errors_are_unbilled: bool,
}

impl CostGuard<'_> {
    fn finish(&mut self, response: &Result<HttpResponse>) {
        if matches!(response, Ok(value) if (200..300).contains(&value.status)
            || (value.status >= 400 && self.errors_are_unbilled))
        {
            self.may_have_cost = false;
        }
    }
}

impl Drop for CostGuard<'_> {
    fn drop(&mut self) {
        if self.may_have_cost {
            self.uncertain.store(true, Ordering::SeqCst);
        }
    }
}

#[async_trait::async_trait]
impl Transport for ProviderAttempt<'_> {
    async fn searxng(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let mut guard = self.guard(&request);
        let result = self.inner.searxng(owner, job, request, stop).await;
        guard.finish(&result);
        result
    }

    async fn get(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let mut guard = self.guard(&request);
        let result = self.inner.get(owner, job, request, stop).await;
        guard.finish(&result);
        result
    }

    async fn post(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        body: Vec<u8>,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let mut guard = self.guard(&request);
        let result = self.inner.post(owner, job, request, body, stop).await;
        guard.finish(&result);
        result
    }

    async fn browser(
        &self,
        _owner: u32,
        _job: Uuid,
        _request: BrowserRequest<'_>,
        _stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        Err(ErrorCode::PolicyDenied)
    }
}

struct Activity {
    closed: bool,
    count: usize,
    error: Option<ErrorCode>,
    reason: Option<JobState>,
}
struct RunningJob {
    owner: u32,
    connection: Uuid,
    deadline: Instant,
    stop: CancellationToken,
    activity: Mutex<Activity>,
    changed: Notify,
    closing: tokio::sync::Mutex<()>,
}

fn close_error(reason: JobState) -> ErrorCode {
    match reason {
        JobState::Interrupted => ErrorCode::EgressChanged,
        JobState::Expired => ErrorCode::Timeout,
        _ => ErrorCode::Cancelled,
    }
}

impl RunningJob {
    fn close(&self, reason: JobState) -> Result<()> {
        self.stop.cancel();
        let mut activity = self.activity.lock().map_err(|_| ErrorCode::Storage)?;
        activity.closed = true;
        activity.reason.get_or_insert(reason);
        activity.error.get_or_insert(close_error(reason));
        Ok(())
    }
}

struct StartingJob {
    connection: Uuid,
    published: AtomicBool,
    invalidated: Mutex<Option<(JobState, ErrorCode)>>,
    stop: CancellationToken,
    done: CancellationToken,
    outcome: Mutex<Option<Result<()>>>,
}

struct StartTask {
    owner: u32,
    limits: RequestedLimits,
    ticket: Uuid,
    pending: Arc<StartingJob>,
    stop: CancellationToken,
    response: oneshot::Sender<Result<(Job, Arc<RunningJob>)>>,
    ack: oneshot::Receiver<()>,
}

impl StartingJob {
    fn invalidate(&self, reason: JobState, error: ErrorCode) -> Result<()> {
        let result =
            self.invalidated
                .lock()
                .map_err(|_| ErrorCode::Storage)
                .map(|mut invalidated| {
                    invalidated.get_or_insert((reason, error));
                });
        self.stop.cancel();
        result
    }

    fn invalidated(&self) -> Result<Option<(JobState, ErrorCode)>> {
        Ok(*self.invalidated.lock().map_err(|_| ErrorCode::Storage)?)
    }

    fn complete(&self, outcome: Result<()>) {
        if let Ok(mut value) = self.outcome.lock() {
            *value = Some(outcome);
        }
        self.done.cancel();
    }

    async fn wait(&self) -> Result<()> {
        self.done.cancelled().await;
        self.outcome
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .unwrap_or(Err(ErrorCode::Storage))
    }
}

struct OperationLease(Arc<RunningJob>);
impl Drop for OperationLease {
    fn drop(&mut self) {
        if let Ok(mut activity) = self.0.activity.lock() {
            activity.count -= 1;
        }
        self.0.changed.notify_waiters();
    }
}
struct State {
    jobs: HashMap<Uuid, Arc<RunningJob>>,
    starting: HashMap<Uuid, Arc<StartingJob>>,
    accepting: bool,
    egress: EgressState,
}

struct CleanupSelection {
    jobs: Vec<(u32, Uuid, Arc<RunningJob>)>,
    starting: Vec<Arc<StartingJob>>,
    reason: JobState,
    stopped: Result<()>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CleanupKey {
    Job(Uuid),
    Start(usize),
}

/// The RPC loop supervises one cleanup per selected job or start. Keeping an
/// Arc for each start also prevents pointer reuse before its result is reaped.
pub(crate) struct CleanupSupervisor {
    tasks: JoinSet<(CleanupKey, Result<()>)>,
    jobs: HashSet<Uuid>,
    starts: HashMap<usize, Arc<StartingJob>>,
    limit: usize,
}

impl CleanupSupervisor {
    pub(crate) fn new(active_jobs: usize) -> Self {
        Self {
            tasks: JoinSet::new(),
            jobs: HashSet::new(),
            starts: HashMap::new(),
            // A start can also be registered as a job, and completed tasks
            // may not yet have been reaped when replacement jobs appear.
            limit: active_jobs.saturating_mul(4),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn completed(
        &mut self,
        result: std::result::Result<(CleanupKey, Result<()>), tokio::task::JoinError>,
    ) -> Result<()> {
        let (key, result) = result.map_err(|_| ErrorCode::WorkerFailed)?;
        match key {
            CleanupKey::Job(id) => {
                self.jobs.remove(&id);
            }
            CleanupKey::Start(id) => {
                self.starts.remove(&id);
            }
        }
        result
    }

    pub(crate) async fn next(&mut self) -> Result<()> {
        match self.tasks.join_next().await {
            Some(result) => self.completed(result),
            None => Ok(()),
        }
    }

    fn schedule(&mut self, service: &Arc<Service>, selection: CleanupSelection) -> Result<()> {
        while let Some(result) = self.tasks.try_join_next() {
            self.completed(result)?;
        }
        for (owner, id, job) in selection.jobs {
            if self.jobs.contains(&id) {
                continue;
            }
            if self.tasks.len() >= self.limit {
                return Err(ErrorCode::Capacity);
            }
            self.jobs.insert(id);
            let service = service.clone();
            let reason = selection.reason;
            self.tasks.spawn(async move {
                let result = service
                    .close_registered_job(owner, id, job, reason)
                    .await
                    .map(|_| ());
                (CleanupKey::Job(id), result)
            });
        }
        for pending in selection.starting {
            let id = Arc::as_ptr(&pending) as usize;
            if self.starts.contains_key(&id) {
                continue;
            }
            if self.tasks.len() >= self.limit {
                return Err(ErrorCode::Capacity);
            }
            self.starts.insert(id, pending.clone());
            self.tasks
                .spawn(async move { (CleanupKey::Start(id), pending.wait().await) });
        }
        selection.stopped
    }
}

#[derive(Clone)]
struct SearchRecord {
    source_id: Uuid,
    data: Value,
    partial: bool,
    empty: bool,
}

pub struct Service {
    config: Config,
    ledger: Arc<Ledger>,
    store: Arc<EvidenceStore>,
    http: Arc<dyn Transport>,
    search_providers: Vec<Arc<dyn SearchProvider>>,
    scrape_providers: Vec<Arc<dyn ScrapeProvider>>,
    summarize_providers: Vec<Arc<dyn SummarizeProvider>>,
    fetcher: Arc<Fetcher>,
    browser: Option<crate::browser::manager::Manager>,
    searches: Cache<SearchRecord>,
    policy: String,
    reports: Reports,
    state: Mutex<State>,
    crawl_pacing: Mutex<HashMap<String, Instant>>,
    #[cfg(test)]
    start_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Dependencies are constructed from operator configuration, never tool input.
pub struct Dependencies {
    pub ledger: Arc<Ledger>,
    pub store: Arc<EvidenceStore>,
    pub http: Arc<dyn Transport>,
    pub parser: Option<Arc<dyn Parser>>,
    pub search_providers: Vec<Arc<dyn SearchProvider>>,
    pub scrape_providers: Vec<Arc<dyn ScrapeProvider>>,
    /// Empty unless the operator separately enabled summarization; every other
    /// operation works without it.
    pub summarize_providers: Vec<Arc<dyn SummarizeProvider>>,
}

impl Service {
    /// Called by the authenticated RPC layer after a failure. Only typed input
    /// limits and fixed service-authored reason codes enter this diagnostic.
    pub fn failure(
        &self,
        tool: Tool,
        arguments: &Value,
        code: ErrorCode,
    ) -> crate::error::ToolFailure {
        let mut failure = crate::error::ToolFailure::from(code);
        if code == ErrorCode::InvalidRequest
            && tool == Tool::ResearchJob
            && let Ok(JobArgs::Start { limits }) = parse(arguments.clone())
        {
            let violations = limits.violations(&self.config.limits);
            if !violations.is_empty() {
                failure.details = Some(crate::error::ErrorDetails::JobLimits { violations });
            }
        }
        failure
    }

    pub fn new(config: Config, dependencies: Dependencies) -> Result<Arc<Self>> {
        config.validate()?;
        let Dependencies {
            ledger,
            store,
            http,
            parser,
            search_providers,
            scrape_providers,
            summarize_providers,
        } = dependencies;
        let fetcher = Arc::new(Fetcher::new(
            config.clone(),
            http.clone(),
            parser,
            ledger.clone(),
            store.clone(),
        )?);
        let browser = if config.browser.enable {
            Some(crate::browser::manager::Manager::new(
                &config,
                store.temporary_directory().to_owned(),
                fetcher.clone(),
                ledger.clone(),
            )?)
        } else {
            None
        };
        let policy = sha256(&serde_json::to_vec(&config).map_err(|_| ErrorCode::InvalidRequest)?);
        let report_bytes = config.limits.report_bytes as usize;
        let report_seconds = config.limits.report_seconds;
        Ok(Arc::new(Self {
            config,
            ledger,
            store,
            http,
            search_providers,
            scrape_providers,
            summarize_providers,
            fetcher,
            browser,
            policy,
            searches: Cache::new(256, 16 * 1024 * 1024)?,
            reports: Reports::new(report_bytes, report_seconds),
            state: Mutex::new(State {
                jobs: HashMap::new(),
                starting: HashMap::new(),
                accepting: true,
                egress: EgressState::offline(),
            }),
            crawl_pacing: Mutex::new(HashMap::new()),
            #[cfg(test)]
            start_hook: Mutex::new(None),
        }))
    }

    pub fn allowed_uids(&self) -> &[u32] {
        &self.config.allowed_client_uids
    }

    /// Operator limits for callers that own a `Service` but not its `Config`
    /// (the RPC layer sizes its connection and request admission from here).
    pub fn limits(&self) -> &Limits {
        &self.config.limits
    }

    /// Read-only local state, not provider health, job capacity or a reservation.
    /// The effective-config hash is distinct from the raw configuration file hash.
    fn readiness(&self, owner: u32) -> Result<Value> {
        let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        let observed_at = chrono::Utc::now().timestamp();
        let egress = &state.egress;
        Ok(json!({
            "schema_version": 1,
            "caller_uid": owner,
            "policy_sha256": self.policy,
            "accepting": state.accepting,
            "observed_at": observed_at,
            "egress": {
                "mode": egress.mode,
                "generation": (!egress.generation.is_nil()).then_some(egress.generation),
                "valid_until": egress.valid_until,
                "lease_valid": egress.valid_at(observed_at),
            },
            "untrusted": true,
        }))
    }

    /// Report only installed, operator-granted capabilities after privacy
    /// filtering. Never expose credential names, paths or endpoint overrides.
    fn capabilities(&self) -> Value {
        let providers = |order: &[String], capability, installed: Vec<&str>| {
            order.iter().filter(|name| {
                installed.contains(&name.as_str())
                    && self.config.provider_allowed(name, capability)
            }).map(|name| {
                let provider = &self.config.providers[name];
                json!({
                    "provider":name,
                    "request_micro_usd":provider.request_micro_usd.unwrap_or(0),
                    "storage":if self.config.privacy == Privacy::Strict || !provider.storage_rights {"job"} else {"persistent"},
                })
            }).collect::<Vec<_>>()
        };
        json!({
            "privacy":self.config.privacy,
            "http":true,
            "browser":self.browser.is_some(),
            "search":providers(&self.config.search_order, Capability::Search, self.search_providers.iter().map(|p| p.name()).collect()),
            "scrape":providers(&self.config.scrape_order, Capability::Scrape, self.scrape_providers.iter().map(|p| p.name()).collect()),
            "summarize":providers(&self.config.summarize_order, Capability::Summarize, self.summarize_providers.iter().map(|p| p.name()).collect()),
        })
    }

    async fn start(
        self: &Arc<Self>,
        owner: u32,
        connection: Uuid,
        limits: RequestedLimits,
        stop: CancellationToken,
    ) -> Result<Job> {
        let pending = Arc::new(StartingJob {
            connection,
            published: AtomicBool::new(false),
            invalidated: Mutex::new(None),
            stop: CancellationToken::new(),
            done: CancellationToken::new(),
            outcome: Mutex::new(None),
        });
        let ticket = Uuid::new_v4();
        {
            let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            if !state.accepting || stop.is_cancelled() {
                return Err(ErrorCode::Cancelled);
            }
            let pending_count = state
                .starting
                .values()
                .filter(|start| !start.published.load(Ordering::Acquire))
                .count();
            if state.starting.len() >= self.config.limits.active_jobs
                || state.jobs.len() + pending_count >= self.config.limits.active_jobs
            {
                return Err(ErrorCode::Capacity);
            }
            state.starting.insert(ticket, pending.clone());
        }
        let (response_tx, mut response_rx) = oneshot::channel();
        let (ack_tx, ack_rx) = oneshot::channel();
        let service = self.clone();
        let worker_pending = pending.clone();
        let worker_stop = stop.clone();
        // A caller's runtime can be destroyed while SQLite is committing. The
        // bounded start ticket owns an independent thread and runtime until the
        // handoff or rejection has been reconciled.
        let spawned = std::thread::Builder::new()
            .name("research-start".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ErrorCode::Storage)?;
                    runtime.block_on(service.start_pending(StartTask {
                        owner,
                        limits,
                        ticket,
                        pending: worker_pending.clone(),
                        stop: worker_stop,
                        response: response_tx,
                        ack: ack_rx,
                    }))
                }));
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        // A panic may have followed an ambiguous commit. Never
                        // allow a surviving service to admit that unknown job.
                        if let Ok(mut state) = service.state.lock() {
                            state.accepting = false;
                        }
                        Err(ErrorCode::Storage)
                    }
                };
                let outcome = match service.state.lock() {
                    Ok(mut state) => {
                        state.starting.remove(&ticket);
                        outcome
                    }
                    Err(_) => Err(ErrorCode::Storage),
                };
                worker_pending.complete(outcome);
            });
        if spawned.is_err() {
            if let Ok(mut state) = self.state.lock() {
                state.starting.remove(&ticket);
            }
            pending.complete(Err(ErrorCode::Storage));
            return Err(ErrorCode::Storage);
        }

        let response = tokio::select! {
            biased;
            _ = stop.cancelled() => Err(ErrorCode::Cancelled),
            _ = pending.stop.cancelled() => Err(
                pending.invalidated()
                    .map(|value| value.map_or(ErrorCode::Cancelled, |(_, error)| error))
                    .unwrap_or(ErrorCode::Storage)
            ),
            response = &mut response_rx => response.unwrap_or(Err(ErrorCode::Storage)),
        };
        let (job, running) = match response {
            Ok(value) => value,
            Err(error) => {
                drop(response_rx);
                drop(ack_tx);
                pending.wait().await?;
                return Err(error);
            }
        };
        // A successful response is handed off only while the same job and
        // pending ticket are still valid. Dropping the receiver or the ack
        // makes the detached starter close the durable job instead.
        let handoff = (|| {
            let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            if let Some((_, error)) = pending.invalidated()? {
                return Err(error);
            }
            if !state.accepting || stop.is_cancelled() {
                return Err(ErrorCode::Cancelled);
            }
            if !state
                .starting
                .get(&ticket)
                .is_some_and(|entry| Arc::ptr_eq(entry, &pending))
                || !state
                    .jobs
                    .get(&job.id)
                    .is_some_and(|entry| Arc::ptr_eq(entry, &running))
            {
                return Err(ErrorCode::JobClosed);
            }
            let mut activity = running.activity.lock().map_err(|_| ErrorCode::Storage)?;
            if activity.reason.is_some() || running.stop.is_cancelled() {
                return Err(activity.error.unwrap_or(ErrorCode::JobClosed));
            }
            if Instant::now() >= running.deadline
                || chrono::Utc::now().timestamp() >= job.deadline_at
            {
                return Err(ErrorCode::Timeout);
            }
            ack_tx.send(()).map_err(|_| ErrorCode::Storage)?;
            activity.closed = false;
            Ok(())
        })();
        if let Err(error) = handoff {
            pending.wait().await?;
            return Err(error);
        }
        Ok(job)
    }

    async fn start_pending(self: &Arc<Self>, request: StartTask) -> Result<()> {
        let StartTask {
            owner,
            limits,
            ticket,
            pending,
            stop,
            response,
            ack,
        } = request;
        let connection = pending.connection;
        #[cfg(test)]
        {
            let hook = self
                .start_hook
                .lock()
                .map_err(|_| ErrorCode::Storage)?
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        let started_at = Instant::now();
        // This runs on the ticket's own thread, not a caller's Tokio worker.
        let job = match self.ledger.start(owner, limits) {
            Ok(job) => job,
            Err(error) => {
                let _ = response.send(Err(error));
                return if error == ErrorCode::Storage {
                    Err(error)
                } else {
                    Ok(())
                };
            }
        };
        let running = Arc::new(RunningJob {
            owner,
            connection,
            deadline: started_at + Duration::from_secs(job.limits.seconds),
            stop: CancellationToken::new(),
            activity: Mutex::new(Activity {
                closed: true,
                count: 0,
                error: None,
                reason: None,
            }),
            changed: Notify::new(),
            closing: tokio::sync::Mutex::new(()),
        });
        // Register even a rejected durable job as closed, so a failed cleanup
        // remains visible to disconnect, shutdown and the expiry pass.
        let registration = (|| {
            let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            let invalid = pending.invalidated()?.or_else(|| {
                if !state.accepting {
                    Some((JobState::Interrupted, ErrorCode::Cancelled))
                } else if stop.is_cancelled()
                    || response.is_closed()
                    || !state
                        .starting
                        .get(&ticket)
                        .is_some_and(|entry| Arc::ptr_eq(entry, &pending))
                {
                    Some((JobState::Cancelled, ErrorCode::Cancelled))
                } else if Instant::now() >= running.deadline
                    || chrono::Utc::now().timestamp() >= job.deadline_at
                {
                    Some((JobState::Expired, ErrorCode::Timeout))
                } else {
                    None
                }
            });
            if let Some((reason, _)) = invalid {
                running.close(reason)?;
            }
            state.jobs.insert(job.id, running.clone());
            pending.published.store(true, Ordering::Release);
            Ok(invalid)
        })();
        let invalid = match registration {
            Ok(invalid) => invalid,
            Err(error) => {
                let _ = response.send(Err(error));
                self.ledger.flush_serialized().await?;
                self.ledger
                    .end_serialized(owner, job.id, JobState::Cancelled)
                    .await?;
                return Err(error);
            }
        };
        if let Some((reason, error)) = invalid {
            let _ = response.send(Err(error));
            return self
                .close_registered_job(owner, job.id, running, reason)
                .await
                .map(|_| ());
        }
        let id = job.id;
        if response.send(Ok((job, running.clone()))).is_ok() && ack.await.is_ok() {
            return Ok(());
        }
        let reason = pending
            .invalidated()?
            .map(|(reason, _)| reason)
            .unwrap_or_else(|| {
                if Instant::now() >= running.deadline {
                    JobState::Expired
                } else {
                    JobState::Cancelled
                }
            });
        running.close(reason)?;
        self.close_registered_job(owner, id, running, reason)
            .await
            .map(|_| ())
    }

    async fn admit(
        &self,
        owner: u32,
        id: Uuid,
        stop: &CancellationToken,
    ) -> Result<(OperationLease, Context)> {
        let (job, generation) = {
            let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            if !state.accepting || stop.is_cancelled() {
                return Err(ErrorCode::Cancelled);
            }
            if state.egress.mode != EgressMode::Ready
                || !state.egress.valid_at(chrono::Utc::now().timestamp())
            {
                return Err(ErrorCode::EgressUnavailable);
            }
            let job = state
                .jobs
                .get(&id)
                .filter(|job| job.owner == owner)
                .ok_or(ErrorCode::JobClosed)?
                .clone();
            {
                let activity = job.activity.lock().map_err(|_| ErrorCode::Storage)?;
                if activity.closed || job.stop.is_cancelled() || Instant::now() >= job.deadline {
                    return Err(ErrorCode::JobClosed);
                }
                if activity.count >= self.config.limits.job_operations {
                    return Err(ErrorCode::Capacity);
                }
            }
            (job, state.egress.generation)
        };
        let ledger = self.ledger.clone();
        let lookup = tokio::task::spawn_blocking(move || ledger.get(owner, id));
        let ledger_job = tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(ErrorCode::Cancelled),
            _ = job.stop.cancelled() => return Err(ErrorCode::JobClosed),
            _ = tokio::time::sleep_until(job.deadline) => return Err(ErrorCode::JobClosed),
            result = lookup => result.map_err(|_| ErrorCode::Storage)??,
        };
        let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        if !state.accepting || stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        if state.egress.mode != EgressMode::Ready
            || !state.egress.valid_at(chrono::Utc::now().timestamp())
        {
            return Err(ErrorCode::EgressUnavailable);
        }
        if state.egress.generation != generation {
            return Err(ErrorCode::EgressChanged);
        }
        if !state
            .jobs
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &job))
        {
            return Err(ErrorCode::JobClosed);
        }
        let mut activity = job.activity.lock().map_err(|_| ErrorCode::Storage)?;
        if activity.closed
            || job.stop.is_cancelled()
            || Instant::now() >= job.deadline
            || ledger_job.state != JobState::Active
            || chrono::Utc::now().timestamp() >= ledger_job.deadline_at
        {
            return Err(ErrorCode::JobClosed);
        }
        if activity.count >= self.config.limits.job_operations {
            return Err(ErrorCode::Capacity);
        }
        activity.count += 1;
        drop(activity);
        let context = Context {
            owner,
            job: id,
            deadline: job.deadline,
            stop: job.stop.child_token(),
        };
        Ok((OperationLease(job), context))
    }

    fn retain_source(
        &self,
        owner: u32,
        source: &crate::archive::Source,
    ) -> Result<Option<OperationLease>> {
        let ephemeral = self.config.privacy == Privacy::Strict
            || source
                .warnings
                .iter()
                .any(|warning| matches!(warning, SourceWarning::StorageNotPermitted));
        let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        let Some(job) = state
            .jobs
            .get(&source.job_id)
            .filter(|job| job.owner == owner)
        else {
            return if ephemeral {
                Err(ErrorCode::SourceExpired)
            } else {
                Ok(None)
            };
        };
        let mut activity = job.activity.lock().map_err(|_| ErrorCode::Storage)?;
        if activity.closed {
            return Err(ErrorCode::SourceExpired);
        }
        if activity.count >= self.config.limits.job_operations {
            return Err(ErrorCode::Capacity);
        }
        activity.count += 1;
        Ok(Some(OperationLease(job.clone())))
    }

    async fn read_job(&self, owner: u32, id: Uuid) -> Result<Job> {
        let ledger = self.ledger.clone();
        tokio::task::spawn_blocking(move || ledger.get(owner, id))
            .await
            .map_err(|_| ErrorCode::Storage)?
    }

    pub async fn close_job(
        self: &Arc<Self>,
        owner: u32,
        id: Uuid,
        reason: JobState,
    ) -> Result<Job> {
        if !matches!(
            reason,
            JobState::Completed | JobState::Cancelled | JobState::Interrupted | JobState::Expired
        ) {
            return Err(ErrorCode::InvalidRequest);
        }
        let job = {
            let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            let job = state
                .jobs
                .get(&id)
                .filter(|job| job.owner == owner)
                .cloned();
            if let Some(job) = &job {
                job.close(reason)?;
            }
            job
        };
        // Once close has begun, cleanup must outlive the caller's future.
        let service = self.clone();
        tokio::spawn(async move {
            if let Some(job) = job {
                service.close_registered_job(owner, id, job, reason).await
            } else {
                service.ledger.flush_serialized().await?;
                service.read_job(owner, id).await
            }
        })
        .await
        .map_err(|_| ErrorCode::Storage)?
    }

    async fn close_registered_job(
        self: &Arc<Self>,
        owner: u32,
        id: Uuid,
        job: Arc<RunningJob>,
        reason: JobState,
    ) -> Result<Job> {
        // Concurrent cancel/finish/disconnect callers all observe completed cleanup.
        let _closing = job.closing.lock().await;
        let registered = self
            .state
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .jobs
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &job));
        if !registered {
            self.ledger.flush_serialized().await?;
            return self.read_job(owner, id).await;
        }
        loop {
            let changed = job.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if job.activity.lock().map_err(|_| ErrorCode::Storage)?.count == 0 {
                break;
            }
            changed.await;
        }
        let reason = job
            .activity
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .reason
            .unwrap_or(reason);
        // Resource cleanup must not be suppressed by a failed accounting
        // barrier, or by a failure in a different resource. Browser sessions
        // close before their temporary evidence is removed.
        let browser = if let Some(browser) = &self.browser {
            browser.finish_job(owner, id).await
        } else {
            Ok(())
        };
        // Store removal may delete a directory, so do not block the RPC
        // runtime while attempting the independent synchronous cleanups.
        let service = self.clone();
        let resources = tokio::task::spawn_blocking(move || {
            let fetch = service.fetcher.finish_job(owner, id);
            let searches = service.searches.remove_job(owner, id);
            let store = service.store.finish_job(owner, id);
            let reports = service.reports.finish_job(owner, id);
            browser.and(fetch).and(searches).and(store).and(reports)
        })
        .await
        .unwrap_or(Err(ErrorCode::Storage));
        // Drained operations have dropped their reservations. Flush all queued
        // settlements, and never commit a terminal state after either a failed
        // barrier or failed resource cleanup. Keep the closed job tracked so
        // subsequent cleanup can retry without admitting more work.
        self.ledger.flush_serialized().await?;
        resources?;
        // In unguarded mode end_serialized uses synchronous SQLite; in guarded
        // mode it awaits the ledger worker. Neither may block the RPC reactor.
        let ledger = self.ledger.clone();
        let runtime = tokio::runtime::Handle::current();
        let finished = tokio::task::spawn_blocking(move || {
            runtime.block_on(ledger.end_serialized(owner, id, reason))
        })
        .await
        .map_err(|_| ErrorCode::Storage)??;
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        if state
            .jobs
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &job))
        {
            state.jobs.remove(&id);
        }
        Ok(finished)
    }

    fn stop_selected(
        jobs: &[(u32, Uuid, Arc<RunningJob>)],
        starting: &[Arc<StartingJob>],
        reason: JobState,
        error: ErrorCode,
    ) -> Result<()> {
        let mut outcome = Ok(());
        for pending in starting {
            if let Err(error) = pending.invalidate(reason, error) {
                outcome = outcome.and(Err(error));
            }
        }
        for (_, _, job) in jobs {
            if let Err(error) = job.close(reason) {
                outcome = outcome.and(Err(error));
            }
        }
        outcome
    }

    async fn finish_jobs(
        self: &Arc<Self>,
        jobs: Vec<(u32, Uuid, Arc<RunningJob>)>,
        starting: Vec<Arc<StartingJob>>,
        reason: JobState,
    ) -> Result<()> {
        // Spawn every close before waiting for any one ledger operation, so a
        // stalled or failed close cannot suppress the other jobs' cleanup.
        let tasks: Vec<_> = jobs
            .into_iter()
            .map(|(owner, id, job)| {
                let service = self.clone();
                tokio::spawn(
                    async move { service.close_registered_job(owner, id, job, reason).await },
                )
            })
            .collect();
        let mut outcome = Ok(());
        for pending in starting {
            if let Err(error) = pending.wait().await {
                outcome = outcome.and(Err(error));
            }
        }
        for task in tasks {
            match task.await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => outcome = outcome.and(Err(error)),
                Err(_) => outcome = outcome.and(Err(ErrorCode::Storage)),
            }
        }
        outcome
    }

    pub async fn disconnect(self: &Arc<Self>, connection: Uuid) -> Result<()> {
        let (jobs, starting, stopped) = {
            let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            let jobs: Vec<_> = state
                .jobs
                .iter()
                .filter(|(_, job)| job.connection == connection)
                .map(|(id, job)| (job.owner, *id, job.clone()))
                .collect();
            let starting: Vec<_> = state
                .starting
                .values()
                .filter(|start| start.connection == connection)
                .cloned()
                .collect();
            let stopped =
                Self::stop_selected(&jobs, &starting, JobState::Cancelled, ErrorCode::Cancelled);
            (jobs, starting, stopped)
        };
        let finished = self.finish_jobs(jobs, starting, JobState::Cancelled).await;
        stopped.and(finished)
    }

    pub async fn shutdown(self: &Arc<Self>) -> Result<()> {
        let (jobs, starting, stopped) = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            state.accepting = false;
            let jobs: Vec<_> = state
                .jobs
                .iter()
                .map(|(id, job)| (job.owner, *id, job.clone()))
                .collect();
            let starting: Vec<_> = state.starting.values().cloned().collect();
            let stopped = Self::stop_selected(
                &jobs,
                &starting,
                JobState::Interrupted,
                ErrorCode::Cancelled,
            );
            (jobs, starting, stopped)
        };
        let finished = self
            .finish_jobs(jobs, starting, JobState::Interrupted)
            .await;
        stopped.and(finished)?;
        self.store.maintenance().await
    }

    fn select_egress(&self, next: EgressState) -> Result<CleanupSelection> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        // Jobs may be created while startup is still Offline, but work is
        // not admitted until Ready. Repeated Offline polls must not turn
        // those waiting jobs into Interrupted. Once a job has observed a
        // non-Offline generation, loss or replacement remains fail-closed.
        let had_egress = state.egress.mode != EgressMode::Offline;
        let interrupt = (had_egress && next.mode == EgressMode::Offline)
            || (had_egress
                && !state.egress.generation.is_nil()
                && next.generation != state.egress.generation);
        state.egress = next;
        let (jobs, starting, stopped) = if interrupt {
            let jobs: Vec<_> = state
                .jobs
                .iter()
                .map(|(id, job)| (job.owner, *id, job.clone()))
                .collect();
            let starting: Vec<_> = state.starting.values().cloned().collect();
            let stopped = Self::stop_selected(
                &jobs,
                &starting,
                JobState::Interrupted,
                ErrorCode::EgressChanged,
            );
            (jobs, starting, stopped)
        } else {
            (Vec::new(), Vec::new(), Ok(()))
        };
        Ok(CleanupSelection {
            jobs,
            starting,
            reason: JobState::Interrupted,
            stopped,
        })
    }

    fn select_expired(&self) -> Result<CleanupSelection> {
        let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        let jobs: Vec<_> = state
            .jobs
            .iter()
            .filter(|(_, job)| Instant::now() >= job.deadline)
            .map(|(id, job)| (job.owner, *id, job.clone()))
            .collect();
        let stopped = Self::stop_selected(&jobs, &[], JobState::Expired, ErrorCode::Timeout);
        Ok(CleanupSelection {
            jobs,
            starting: Vec::new(),
            reason: JobState::Expired,
            stopped,
        })
    }

    async fn finish_selection(self: &Arc<Self>, selection: CleanupSelection) -> Result<()> {
        let finished = self
            .finish_jobs(selection.jobs, selection.starting, selection.reason)
            .await;
        selection.stopped.and(finished)
    }

    /// Ready/Draining/Offline comes only from the root-owned, short-lived lease.
    /// Draining pauses admission; loss or a new exit generation interrupts jobs.
    /// This public form waits for all selected cleanup.
    pub async fn update_egress(self: &Arc<Self>, next: EgressState) -> Result<()> {
        self.finish_selection(self.select_egress(next)?).await
    }

    pub async fn expire(self: &Arc<Self>) -> Result<()> {
        self.finish_selection(self.select_expired()?).await
    }

    // The RPC loop applies each observation synchronously, then supervises
    // bounded, deduplicated cleanup without delaying the next observation.
    pub(crate) fn observe_egress(
        self: &Arc<Self>,
        next: EgressState,
        cleanup: &mut CleanupSupervisor,
    ) -> Result<()> {
        cleanup.schedule(self, self.select_egress(next)?)
    }

    pub(crate) fn observe_expiry(self: &Arc<Self>, cleanup: &mut CleanupSupervisor) -> Result<()> {
        cleanup.schedule(self, self.select_expired()?)
    }

    /// Resolve the profile for a browser session that is starting now from the
    /// latest observed exit region. A session already created keeps its own
    /// captured profile, so a later region change only affects new sessions.
    fn current_profile(&self) -> Result<Profile> {
        let region = self
            .state
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .egress
            .region
            .clone();
        Ok(Profile::resolve(
            self.config.browser.profile,
            region.as_deref(),
        ))
    }

    pub async fn maintenance(&self) -> Result<()> {
        if let Some(browser) = &self.browser {
            browser.maintenance().await?;
        }
        self.searches.maintenance()?;
        self.fetcher.maintenance()?;
        self.reports.maintenance()?;
        self.store.maintenance().await
    }

    pub async fn call(
        self: &Arc<Self>,
        owner: u32,
        connection: Uuid,
        tool: Tool,
        arguments: Value,
        stop: CancellationToken,
    ) -> Result<Value> {
        if stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        // Transport peer checks are repeated here for in-process callers.
        if !self.allowed_uids().contains(&owner) {
            return Err(ErrorCode::PermissionDenied);
        }
        let mut operation_lease = None;
        let mut started_job = None;
        let (scope, value) = match tool {
            Tool::ResearchJob => {
                let args: JobArgs = parse(arguments)?;
                let (job, include_sources) = match args {
                    JobArgs::Providers {} => {
                        return Ok(json!({"capabilities": self.capabilities(), "untrusted": true}));
                    }
                    JobArgs::Readiness {} => return self.readiness(owner),
                    JobArgs::Start { limits } => {
                        let job = self.start(owner, connection, limits, stop.clone()).await?;
                        started_job = Some(job.id);
                        (job, false)
                    }
                    JobArgs::Status { job_id } => {
                        let job = self.read_job(owner, job_id).await?;
                        if job.state != JobState::Active {
                            self.ledger.flush_serialized().await?;
                        }
                        (job, true)
                    }
                    JobArgs::Finish { job_id } => (
                        self.close_job(owner, job_id, JobState::Completed).await?,
                        true,
                    ),
                    JobArgs::Cancel { job_id } => (
                        self.close_job(owner, job_id, JobState::Cancelled).await?,
                        true,
                    ),
                };
                let source_ids = if include_sources {
                    self.store.job_sources(owner, job.id).await?
                } else {
                    Vec::new()
                };
                (
                    None,
                    json!({"remaining":job.remaining(),"capabilities":self.capabilities(),"job":job,"source_ids":source_ids,"untrusted":true}),
                )
            }
            Tool::ResearchRead => {
                let args = parse(arguments)?;
                let source_id = match &args {
                    ReadArgs::Metadata { source_id }
                    | ReadArgs::Source { source_id, .. }
                    | ReadArgs::PdfPage { source_id, .. } => Some(*source_id),
                    ReadArgs::Report { .. } => None,
                    // A summary is paid, cancellable job work on saved evidence,
                    // admitted exactly like search/fetch/browser.
                    &ReadArgs::Summary {
                        job_id,
                        source_id,
                        representation_id,
                    } => {
                        let (lease, value) = self
                            .run_work(
                                owner,
                                Work::Summarize {
                                    job_id,
                                    source_id,
                                    representation_id,
                                },
                                stop,
                            )
                            .await?;
                        operation_lease = Some(lease);
                        let result = self.reports.bound(
                            owner,
                            Some(job_id),
                            value,
                            self.config.limits.result_bytes,
                        );
                        drop(operation_lease);
                        return result;
                    }
                };
                if let Some(source_id) = source_id {
                    let source = self.store.get(owner, source_id).await?;
                    operation_lease = self.retain_source(owner, &source)?;
                    let value = if matches!(args, ReadArgs::Metadata { .. }) {
                        to_value(source.clone())?
                    } else {
                        self.read(owner, args).await?
                    };
                    (operation_lease.as_ref().map(|_| source.job_id), value)
                } else {
                    (None, self.read(owner, args).await?)
                }
            }
            tool => {
                let work = match tool {
                    Tool::ResearchSearch => Work::Search(parse(arguments)?),
                    Tool::ResearchFetch => Work::Fetch(parse(arguments)?),
                    Tool::ResearchBrowser => Work::Browser(parse(arguments)?),
                    _ => return Err(ErrorCode::InvalidRequest),
                };
                let job_id = work.job_id();
                let (lease, value) = self.run_work(owner, work, stop).await?;
                operation_lease = Some(lease);
                (Some(job_id), value)
            }
        };
        let result = self
            .reports
            .bound(owner, scope, value, self.config.limits.result_bytes);
        drop(operation_lease);
        if result.is_err()
            && let Some(id) = started_job
        {
            self.close_job(owner, id, JobState::Cancelled).await?;
        }
        result
    }

    /// Admit job work and run it under call cancellation, job cancellation and
    /// the job deadline. The lease is returned so the caller releases it only
    /// after the result has been bounded.
    async fn run_work(
        &self,
        owner: u32,
        work: Work,
        stop: CancellationToken,
    ) -> Result<(OperationLease, Value)> {
        let (lease, context) = self.admit(owner, work.job_id(), &stop).await?;
        let work_future = self.work(&context, work);
        tokio::pin!(work_future);
        // Never drop the work future at cancellation: isolated workers
        // kill and reap their children before returning.
        let value = tokio::select! {
            value = &mut work_future => value,
            _ = stop.cancelled() => { context.stop.cancel(); let _ = work_future.await; Err(ErrorCode::Cancelled) },
            _ = context.stop.cancelled() => { let _ = work_future.await; Err(ErrorCode::Cancelled) },
            _ = tokio::time::sleep_until(context.deadline) => { context.stop.cancel(); let _ = work_future.await; Err(ErrorCode::Timeout) },
        };
        if let Some(error) = lease
            .0
            .activity
            .lock()
            .ok()
            .and_then(|activity| activity.error)
        {
            return Err(error);
        }
        Ok((lease, value?))
    }

    async fn work(&self, context: &Context, work: Work) -> Result<Value> {
        let items = match work {
            Work::Search(args) => {
                if args.queries.is_empty()
                    || args.queries.len()
                        > (self.config.limits.queries as usize).min(self.config.limits.search_batch)
                {
                    return Err(ErrorCode::InvalidRequest);
                }
                self.batch(
                    context,
                    args.queries.into_iter().map(Input::Search).collect(),
                )
                .await
            }
            Work::Fetch(args) => {
                if args.urls.is_empty()
                    || args.urls.len()
                        > (self.config.limits.documents as usize)
                            .min(self.config.limits.fetch_batch)
                {
                    return Err(ErrorCode::InvalidRequest);
                }
                let FetchArgs {
                    urls, mode, crawl, ..
                } = args;
                if let Some(crawl) = crawl {
                    // Crawling is local HTTP discovery. Browser rendering and
                    // explicit scrape providers are not crawl transports, so a
                    // combination is a caller error rather than a silent fallback.
                    if !matches!(mode, FetchMode::Http | FetchMode::Auto) {
                        return Err(ErrorCode::InvalidRequest);
                    }
                    crawl.validate()?;
                }
                self.batch(
                    context,
                    urls.into_iter()
                        .map(|url| Input::Fetch(url, mode, crawl))
                        .collect(),
                )
                .await
            }
            Work::Browser(args) => {
                let profile = self.current_profile()?;
                let mut result = self
                    .browser
                    .as_ref()
                    .ok_or(ErrorCode::ProviderUnavailable)?
                    .execute(context, args, &profile)
                    .await?;
                result["usage"] = to_value(self.read_job(context.owner, context.job).await?.usage)?;
                return Ok(result);
            }
            Work::Summarize {
                source_id,
                representation_id,
                ..
            } => {
                return self.summarize(context, source_id, representation_id).await;
            }
        };
        Ok(
            json!({"job_id":context.job,"coverage":Coverage::from_items(&items),"items":items,
            "usage":self.read_job(context.owner, context.job).await?.usage,"untrusted":true,"truncated":false}),
        )
    }

    async fn batch(&self, context: &Context, inputs: Vec<Input>) -> Vec<Item> {
        // HTTP work can overlap at its normal limit; only the render stage
        // waits for a slot. Persistent sessions still share the manager's pool.
        let browser_slots = Semaphore::new(self.config.limits.browser_concurrency.max(1));
        let browser_slots = &browser_slots;
        let mut seen = HashMap::new();
        let mut duplicates = Vec::new();
        let mut unique = Vec::new();
        for (index, input) in inputs.into_iter().enumerate() {
            let key = input.key();
            if let Some(first) = seen.get(&key) {
                duplicates.push((index, *first));
            } else {
                seen.insert(key, index);
                unique.push((index, input));
            }
        }
        let mut items: Vec<Item> = stream::iter(unique)
            .map(|(index, input)| async move {
                if context.stop.is_cancelled() {
                    return Item {
                        state: ItemState::Skipped,
                        ..Item::failed(index, ErrorCode::Cancelled)
                    };
                }
                match input {
                    Input::Search(query) => match self.search(context, &query).await {
                        Ok((record, hit)) => Item {
                            index,
                            state: if record.partial {
                                ItemState::Partial
                            } else if record.empty {
                                ItemState::Empty
                            } else {
                                ItemState::Success
                            },
                            data: Some(json!({"result":record.data,"cache_hit":hit})),
                            error: None,
                            duplicate_of: None,
                        },
                        Err(error) => Item::failed(index, error),
                    },
                    Input::Fetch(url, mode, crawl) => {
                        self.fetch_item(context, index, &url, mode, crawl, browser_slots)
                            .await
                    }
                }
            })
            .buffer_unordered(self.config.limits.http_concurrency)
            .collect()
            .await;
        for (index, first) in duplicates {
            if let Some(original) = items.iter().find(|item| item.index == first) {
                items.push(Item {
                    index,
                    duplicate_of: Some(first),
                    ..original.clone()
                });
            }
        }
        items.sort_by_key(|item| item.index);
        items
    }

    async fn render_fetch(
        &self,
        context: &Context,
        target: &PublicUrl,
        slots: &Semaphore,
    ) -> Result<Value> {
        let browser = self
            .browser
            .as_ref()
            .ok_or(ErrorCode::ProviderUnavailable)?;
        let _permit = tokio::select! {
            biased;
            _ = context.stop.cancelled() => return Err(ErrorCode::Cancelled),
            _ = tokio::time::sleep_until(context.deadline) => return Err(ErrorCode::Timeout),
            permit = slots.acquire() => permit.map_err(|_| ErrorCode::Cancelled)?,
        };
        let profile = self.current_profile()?;
        browser.fetch(context, target, &profile).await
    }

    async fn fetch_item(
        &self,
        context: &Context,
        index: usize,
        url: &str,
        mode: FetchMode,
        crawl: Option<CrawlArgs>,
        slots: &Semaphore,
    ) -> Item {
        let target = match PublicUrl::parse(url) {
            Ok(target) => target,
            Err(error) => return Item::failed(index, error),
        };
        if matches!(mode, FetchMode::Browser) {
            return browser_item(index, self.render_fetch(context, &target, slots).await);
        }
        // An explicit provider request is the only path to a scrape provider.
        // `Auto` never escalates to one, and this branch still runs the robots
        // policy check before any provider is called.
        if matches!(mode, FetchMode::Provider) {
            return self.scrape_item(context, index, &target).await;
        }
        let record = match self.fetcher.fetch(context, &target).await {
            Ok(record) => record,
            Err(error) => return Item::failed(index, error),
        };
        // Crawling reuses the seed's already-extracted links. It never touches
        // the network before the seed fetch above succeeds, and it never crosses
        // the seed origin.
        let crawl_summary = match crawl {
            Some(crawl) => Some(
                self.crawl_seed(
                    context,
                    &target,
                    &record.source.final_url,
                    &record.links,
                    crawl,
                )
                .await,
            ),
            None => None,
        };
        let mut links_truncated = record.links.len() > 8;
        let links: Vec<_> = record
            .links
            .iter()
            .take(8)
            .map(|link| {
                let (label, truncated) = crate::provider::bounded_text(&link.label, 512);
                links_truncated |= truncated;
                json!({"url":link.url,"label":label})
            })
            .collect();
        let mut item = Item {
            index,
            state: if record.error.is_some()
                || record.source.warnings.iter().any(|warning| {
                    matches!(
                        warning,
                        SourceWarning::PartialExtraction
                            | SourceWarning::Truncated
                            | SourceWarning::JavascriptRequired
                            | SourceWarning::PageShell
                            | SourceWarning::StreamingHtmlRecovered
                    )
                }) {
                ItemState::Partial
            } else {
                ItemState::Success
            },
            data: Some(
                json!({"source":SourceBrief::from(&record.source),"raw_source_id":record.raw_source_id,"title":record.title,
                "links":links,"links_truncated":links_truncated,"links_representation":record.source.representations.iter().find(|rep| rep.kind == RepresentationKind::Links),
                "cache_hit":record.cache_hit,"javascript_required":record.javascript_hint}),
            ),
            error: record.error,
            duplicate_of: None,
        };
        // Only a successful HTTP/extraction result can request automatic
        // rendering. Access, policy and extraction errors cannot trigger it.
        let mut item = if matches!(mode, FetchMode::Auto)
            && self.browser.is_some()
            && item.error.is_none()
            && record.javascript_hint
        {
            let mut rendered =
                browser_item(index, self.render_fetch(context, &target, slots).await);
            if !matches!(rendered.state, ItemState::Failed)
                && let Some(data) = rendered.data.as_mut()
            {
                data["http"] = item.data.take().expect("HTTP evidence was assembled above");
                rendered
            } else {
                item.state = ItemState::Partial;
                item.error = rendered.error;
                if let Some(data) = item.data.as_mut() {
                    data["render_error"] = json!(rendered.error);
                    if let Some(details) = rendered
                        .data
                        .as_ref()
                        .and_then(|data| data.get("error_details"))
                    {
                        data["render_error_details"] = details.clone();
                    }
                }
                item
            }
        } else {
            item
        };
        if let (Some(summary), Some(data)) = (crawl_summary, item.data.as_mut()) {
            if summary["partial"] == true {
                item.state = ItemState::Partial;
            }
            data["crawl"] = summary;
        }
        item
    }

    /// Reserve an origin's next automatic request only when it can begin. The
    /// shared map spaces concurrent jobs without holding a lock while waiting.
    async fn wait_for_crawl_slot(
        &self,
        context: &Context,
        origin: &str,
        interval: Duration,
    ) -> Result<()> {
        if interval.is_zero() {
            return Ok(());
        }
        loop {
            if context.stop.is_cancelled() {
                return Err(ErrorCode::Cancelled);
            }
            let now = Instant::now();
            if now >= context.deadline {
                return Err(ErrorCode::Timeout);
            }
            let next = {
                let mut pacing = self.crawl_pacing.lock().map_err(|_| ErrorCode::Storage)?;
                pacing.retain(|_, until| *until > now);
                match pacing.get(origin) {
                    Some(until) => Some(*until),
                    None => {
                        if pacing.len() >= MAX_CRAWL_PACING_ORIGINS {
                            return Err(ErrorCode::Capacity);
                        }
                        pacing.insert(origin.to_owned(), now + interval);
                        None
                    }
                }
            };
            match next {
                None => return Ok(()),
                Some(until) => tokio::select! { biased;
                    _ = context.stop.cancelled() => return Err(ErrorCode::Cancelled),
                    _ = tokio::time::sleep_until(context.deadline) => return Err(ErrorCode::Timeout),
                    _ = tokio::time::sleep_until(until) => {},
                },
            }
        }
    }

    /// Bounded breadth-first crawl of same-origin links discovered from the
    /// seed. Every visited page goes through the normal `Fetcher::fetch` path,
    /// so redirects, robots, budgets, retries, caching and evidence recording
    /// are identical to a directly requested fetch. Discovery robots semantics
    /// are stricter than a selected page: an unavailable/throttled robots
    /// document pauses the origin instead of falling back to reading.
    async fn crawl_seed(
        &self,
        context: &Context,
        seed: &PublicUrl,
        seed_final_url: &str,
        seed_links: &[crate::worker::Link],
        crawl: CrawlArgs,
    ) -> Value {
        let origin = seed.origin();
        // The operator limit is a ceiling: a client can only reduce it.
        let total = usize::from(crawl.pages)
            .min(self.config.limits.crawl_pages as usize)
            .max(1);
        let max_depth = u32::from(crawl.depth).min(self.config.limits.crawl_depth);
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(seed.request_url().to_string());
        if let Ok(final_url) = PublicUrl::parse(seed_final_url) {
            visited.insert(final_url.request_url().to_string());
        }
        let mut queue: VecDeque<(PublicUrl, u32)> = VecDeque::new();
        if max_depth >= 1 {
            for link in seed_links {
                if let Ok(url) = PublicUrl::parse(&link.url)
                    && url.origin() == origin
                {
                    queue.push_back((url, 1));
                }
            }
        }
        let mut pages = Vec::new();
        let (mut fetched, mut skipped, mut failed) = (0usize, 0usize, 0usize);
        let (mut paused, mut partial) = (false, false);
        // A zero/absent/error interval does not block; discovery policy still
        // decides whether an uncertain origin may be crawled.
        let crawl_interval = self
            .fetcher
            .crawl_interval(context, seed)
            .await
            .unwrap_or_default();
        while let Some((url, depth)) = queue.pop_front() {
            if !visited.insert(url.request_url().to_string()) {
                continue;
            }
            if context.stop.is_cancelled() || Instant::now() >= context.deadline {
                partial = true;
                break;
            }
            if fetched >= total.saturating_sub(1) {
                // The page budget counts fetched pages; the seed is one of them.
                partial = true;
                break;
            }
            match self.fetcher.discovery_decision(context, &url).await {
                Ok(DiscoveryDecision::Allowed) => {
                    match self
                        .wait_for_crawl_slot(context, &origin, crawl_interval)
                        .await
                    {
                        Ok(()) => {}
                        Err(ErrorCode::Cancelled | ErrorCode::Timeout) => {
                            partial = true;
                            break;
                        }
                        Err(error) => {
                            failed += 1;
                            partial = true;
                            pages.push(json!({
                                "url": url.as_str(), "depth": depth,
                                "state": ItemState::Failed, "error": error,
                            }));
                            break;
                        }
                    }
                    let attempted = self.fetcher.fetch(context, &url).await;
                    // The slot is consumed even when the request fails.
                    let record = match attempted {
                        Ok(record) => record,
                        Err(ErrorCode::Cancelled) => {
                            partial = true;
                            break;
                        }
                        Err(error) => {
                            failed += 1;
                            partial = true;
                            pages.push(json!({
                                "url": url.as_str(), "depth": depth,
                                "state": ItemState::Failed, "error": error,
                            }));
                            continue;
                        }
                    };
                    fetched += 1;
                    if let Ok(final_url) = PublicUrl::parse(&record.source.final_url) {
                        visited.insert(final_url.request_url().to_string());
                    }
                    if record.error.is_some() {
                        partial = true;
                    }
                    pages.push(crawl_page_data(depth, &record));
                    if depth < max_depth {
                        for link in &record.links {
                            if let Ok(next) = PublicUrl::parse(&link.url)
                                && next.origin() == origin
                            {
                                queue.push_back((next, depth + 1));
                            }
                        }
                    }
                }
                Ok(DiscoveryDecision::Skip) => {
                    skipped += 1;
                    partial = true;
                    pages.push(json!({
                        "url": url.as_str(), "depth": depth, "state": ItemState::Skipped,
                    }));
                }
                Ok(DiscoveryDecision::Pause) => {
                    paused = true;
                    partial = true;
                    break;
                }
                Err(ErrorCode::Cancelled) => {
                    partial = true;
                    break;
                }
                Err(_) => {
                    paused = true;
                    partial = true;
                    break;
                }
            }
        }
        json!({
            "requested_pages": crawl.pages,
            "requested_depth": crawl.depth,
            "effective_pages": total,
            "effective_depth": max_depth,
            "fetched": fetched,
            "skipped": skipped,
            "failed": failed,
            "paused": paused,
            "partial": partial,
            "pages": pages,
        })
    }

    /// Explicit scrape-provider fetch. The selected-page robots decision runs
    /// first through the same local policy path as `Fetcher::fetch`, so a
    /// provider can never be used to route around an access block.
    async fn scrape_item(&self, context: &Context, index: usize, target: &PublicUrl) -> Item {
        // Operator order decides preference, but only providers the
        // configuration explicitly enables and grants for scrape are eligible.
        let providers: Vec<&Arc<dyn ScrapeProvider>> = self
            .config
            .scrape_order
            .iter()
            .filter(|name| {
                self.config
                    .provider_allowed(name.as_str(), Capability::Scrape)
            })
            .filter_map(|name| {
                self.scrape_providers
                    .iter()
                    .find(|provider| provider.name() == name.as_str())
            })
            .collect();
        if providers.is_empty() {
            return Item::failed(index, ErrorCode::ProviderUnavailable);
        }
        if context.stop.is_cancelled() {
            return Item::failed(index, ErrorCode::Cancelled);
        }
        // Charge once per selected item, not per provider or fallback attempt.
        // Admission must precede even the robots request.
        let ledger = self.ledger.clone();
        let owner = context.owner;
        let job = context.job;
        let reservation = match tokio::task::spawn_blocking(move || {
            ledger.reserve(
                owner,
                job,
                Charge {
                    documents: 1,
                    ..Charge::default()
                },
            )
        })
        .await
        {
            Ok(Ok(reservation)) => reservation,
            Ok(Err(error)) => return Item::failed(index, error),
            Err(_) => return Item::failed(index, ErrorCode::Storage),
        };
        if let Err(error) = reservation.finish_serialized(0, Some(0)).await {
            return Item::failed(index, error);
        }
        if context.stop.is_cancelled() {
            return Item::failed(index, ErrorCode::Cancelled);
        }
        let robots_warning = match self.fetcher.selected_page_policy(context, target).await {
            Ok(warning) => warning,
            Err(error) => return Item::failed(index, error),
        };
        let mut last = ErrorCode::ProviderUnavailable;
        let mut provider_attempts = Vec::new();
        let mut last_partial = None;
        for provider in &providers {
            let attempt = ProviderAttempt::new(self.http.as_ref());
            let response = match provider
                .scrape(&attempt, context, target, self.config.limits.pdf_bytes)
                .await
            {
                Ok(response) => response,
                // Only failures that leave cost and access unambiguous may move
                // to another provider. Cancelled/Timeout/EgressUnavailable,
                // policy/access blocks and budget limits return directly.
                Err(error)
                    if matches!(
                        error,
                        ErrorCode::ProviderUnavailable
                            | ErrorCode::Authentication
                            | ErrorCode::RateLimited
                            | ErrorCode::InvalidResponse
                    ) && attempt.fallback_safe() =>
                {
                    last = error;
                    provider_attempts.push(json!({"provider":provider.name(),"error":error}));
                    continue;
                }
                Err(error) => return Item::failed(index, error),
            };
            let name = response.provider;
            let mut warnings = Vec::new();
            if robots_warning {
                warnings.push(SourceWarning::RobotsUnavailable);
            }
            if !response.storage_rights {
                warnings.push(SourceWarning::StorageNotPermitted);
            }
            let mut page_error = response.page_error;
            // A provider may report a redirect, including a new origin. Its
            // reported final destination needs the same access decision as an
            // explicitly selected page before it can become successful evidence.
            if page_error.is_none() && response.url.request_url() != target.request_url() {
                match self
                    .fetcher
                    .selected_page_policy(context, &response.url)
                    .await
                {
                    Ok(unavailable) => {
                        if unavailable {
                            warnings.push(SourceWarning::RobotsUnavailable);
                        }
                    }
                    Err(error) => page_error = Some(error),
                }
            }
            if page_error.is_some() {
                warnings.push(SourceWarning::PartialExtraction);
            }
            // Raw provider JSON, the origin content the provider observed and
            // the provider-derived text keep distinct identities, so observation
            // cannot be mistaken for the provider's own extraction.
            let mut evidence = vec![Evidence {
                kind: RepresentationKind::HttpEntity,
                text: std::str::from_utf8(&response.raw).is_ok(),
                bytes: response.raw,
                extraction_version: format!("{name}-http-json/v1"),
                derived_from: None,
                pdf_page: None,
            }];
            let origin = response
                .origin
                .filter(|_| page_error.is_none())
                .map(|origin| {
                    evidence.push(Evidence {
                        kind: RepresentationKind::HttpEntity,
                        bytes: origin,
                        extraction_version: format!("{name}-rawhtml/v1"),
                        derived_from: Some(0),
                        pdf_page: None,
                        text: false,
                    });
                    evidence.len() - 1
                });
            if page_error.is_none() {
                evidence.push(Evidence {
                    kind: RepresentationKind::Text,
                    bytes: response.text,
                    extraction_version: format!("{name}-markdown/v1"),
                    derived_from: Some(origin.unwrap_or(0)),
                    pdf_page: None,
                    text: true,
                });
            }
            let source = match self
                .store
                .insert(
                    context.owner,
                    NewSource {
                        job_id: context.job,
                        original_url: target.clone(),
                        final_url: response.url,
                        provider: Some(name.into()),
                        retrieved_at: response.retrieved_at,
                        warnings,
                        evidence,
                    },
                    response.storage_rights,
                )
                .await
            {
                Ok(source) => source,
                Err(error) => return Item::failed(index, error),
            };
            let mut item = Item {
                index,
                state: if page_error.is_some() {
                    ItemState::Partial
                } else {
                    ItemState::Success
                },
                data: Some(json!({
                    "source": SourceBrief::from(&source),
                    "raw_source_id": source.id,
                    "title": response.title.unwrap_or_default(),
                    "links": [],
                    "links_truncated": false,
                    "links_representation": Value::Null,
                    "cache_hit": false,
                    "javascript_required": false,
                    "provider": name,
                })),
                error: page_error,
                duplicate_of: None,
            };
            if let Some(error) = page_error
                && matches!(error, ErrorCode::RateLimited | ErrorCode::InvalidResponse)
                && attempt.fallback_safe()
            {
                provider_attempts.push(json!({
                    "provider": name,
                    "source": SourceBrief::from(&source),
                    "error": error,
                }));
                last_partial = Some(item);
                last = error;
                continue;
            }
            if !provider_attempts.is_empty() {
                item.data.as_mut().expect("source data")["provider_attempts"] =
                    json!(provider_attempts);
            }
            return item;
        }
        if let Some(mut item) = last_partial {
            item.data.as_mut().expect("source data")["provider_attempts"] =
                json!(provider_attempts);
            return item;
        }
        Item::failed(index, last)
    }

    async fn search(
        &self,
        context: &Context,
        query: &SearchQuery,
    ) -> Result<(Arc<SearchRecord>, bool)> {
        query.validate()?;
        // Operator order decides preference, but only providers the
        // configuration explicitly enables and grants for search are eligible.
        let providers: Vec<&Arc<dyn SearchProvider>> = self
            .config
            .search_order
            .iter()
            .filter(|name| {
                self.config
                    .provider_allowed(name.as_str(), Capability::Search)
            })
            .filter_map(|name| {
                self.search_providers
                    .iter()
                    .find(|provider| provider.name() == name.as_str())
            })
            .collect();
        if providers.is_empty() {
            return Err(ErrorCode::ProviderUnavailable);
        }
        // The cache may only be shared across jobs when every candidate permits
        // persistent storage, so a fallback cannot silently widen storage rights;
        // the record itself uses the chosen provider's rights below.
        let rights = providers
            .iter()
            .all(|provider| self.config.providers[provider.name()].storage_rights);
        let key = Key::new(
            context.owner,
            (self.config.privacy == Privacy::Strict || !rights).then_some(context.job),
            &self.policy,
            query,
        )?;
        for _ in 0..2 {
            let (record, hit) = self.searches.get_or_init_cancellable(key.clone(), &context.stop, || async {
                let mut last = ErrorCode::ProviderUnavailable;
                for provider in &providers {
                    let attempt = ProviderAttempt::new(self.http.as_ref());
                    match provider.search(&attempt, context, query, self.config.limits.retries, self.config.limits.html_bytes).await {
                        Ok(response) => {
                            let text = serde_json::to_vec(&response.data).map_err(|_| ErrorCode::InvalidResponse)?;
                            let partial = response.data.omitted_results != 0 || response.data.hits.iter().any(|hit| hit.truncated);
                            let empty = response.data.hits.is_empty();
                            let storage_rights = response.storage_rights;
                            let name = response.provider;
                            let evidence = vec![
                                Evidence { kind: RepresentationKind::HttpEntity, bytes: response.raw, extraction_version: format!("{name}-http-json/v1"), derived_from: None, pdf_page: None, text: true },
                                Evidence { kind: RepresentationKind::SearchResults, bytes: text, extraction_version: format!("{name}-web-search/v1"), derived_from: Some(0), pdf_page: None, text: true },
                            ];
                            let source = self.store.insert(context.owner, NewSource {
                                job_id: context.job, original_url: response.url.clone(), final_url: response.url, provider: Some(name.into()), retrieved_at: response.retrieved_at,
                                warnings: if storage_rights { Vec::new() } else { vec![SourceWarning::StorageNotPermitted] }, evidence,
                            }, storage_rights).await?;
                            let data = json!({"provider":name,"source":SourceBrief::from(&source),"results":response.data,"untrusted":true});
                            let weight = serde_json::to_vec(&data).map_err(|_| ErrorCode::InvalidResponse)?.len();
                            return Ok((SearchRecord { source_id: source.id, data, partial, empty }, Duration::from_secs(self.config.retention.cache_seconds), weight));
                        }
                        // Only failures that leave cost and access unambiguous may
                        // move to another provider. Cancelled/Timeout/
                        // EgressUnavailable, policy/access blocks and budget limits
                        // return directly: an uncertain charge or a blocked target
                        // is never replayed or routed around.
                        Err(error) if matches!(error, ErrorCode::ProviderUnavailable | ErrorCode::Authentication | ErrorCode::RateLimited | ErrorCode::InvalidResponse) && attempt.fallback_safe() => {
                            last = error;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(last)
            }).await?;
            if !hit
                || self
                    .store
                    .get(context.owner, record.source_id)
                    .await
                    .is_ok()
            {
                return Ok((record, hit));
            }
            self.searches.invalidate(&key)?;
        }
        Err(ErrorCode::SourceExpired)
    }

    /// Send one saved text representation to a granted summarization provider
    /// and archive the generated text as a new source. The summary is generated
    /// data with its own identity; it never replaces or alters the evidence it
    /// was derived from, and reading that evidence never requires a provider.
    async fn summarize(
        &self,
        context: &Context,
        source_id: Uuid,
        representation_id: Option<Uuid>,
    ) -> Result<Value> {
        // Operator order decides preference, but only providers the
        // configuration explicitly enables and grants for summarize are
        // eligible. Strict privacy never grants it.
        let providers: Vec<&Arc<dyn SummarizeProvider>> = self
            .config
            .summarize_order
            .iter()
            .filter(|name| {
                self.config
                    .provider_allowed(name.as_str(), Capability::Summarize)
            })
            .filter_map(|name| {
                self.summarize_providers
                    .iter()
                    .find(|provider| provider.name() == name.as_str())
            })
            .collect();
        if providers.is_empty() {
            return Err(ErrorCode::ProviderUnavailable);
        }
        let source = self.store.get(context.owner, source_id).await?;
        let representation_id = match representation_id {
            Some(id) => id,
            None => {
                SourceBrief::from(&source)
                    .primary_representation
                    .filter(|representation| representation.text)
                    .ok_or(ErrorCode::NotFound)?
                    .id
            }
        };
        let (representation, text, input_truncated) = self
            .store
            .text(
                context.owner,
                source_id,
                representation_id,
                self.config.limits.summary_input_bytes,
            )
            .await?;
        let characters = text.chars().count();
        let input = json!({
            "source_id": source_id,
            "representation_id": representation.id,
            "sha256": representation.sha256,
            "characters": characters,
            "truncated": input_truncated,
        });
        if text.trim().is_empty() {
            // Nothing to summarize: no paid request is made.
            return Ok(json!({
                "job_id": context.job, "state": ItemState::Empty, "input": input,
                "summary": "", "generated": true,
                "usage": self.read_job(context.owner, context.job).await?.usage,
                "untrusted": true, "truncated": false,
            }));
        }
        let subject = PublicUrl::parse(&source.final_url)?;
        let summary_input = SummaryInput {
            url: subject.as_str(),
            text: &text,
            truncated: input_truncated,
        };
        let mut last = ErrorCode::ProviderUnavailable;
        for provider in &providers {
            let attempt = ProviderAttempt::new(self.http.as_ref());
            let response = match provider
                .summarize(
                    &attempt,
                    context,
                    &summary_input,
                    self.config.limits.summary_output_tokens,
                    self.config.limits.html_bytes,
                )
                .await
            {
                Ok(response) => response,
                // Only failures that leave cost and access unambiguous may move
                // to another provider; uncertain charges are never replayed.
                Err(error)
                    if matches!(
                        error,
                        ErrorCode::ProviderUnavailable
                            | ErrorCode::Authentication
                            | ErrorCode::RateLimited
                            | ErrorCode::InvalidResponse
                    ) && attempt.fallback_safe() =>
                {
                    last = error;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let name = response.provider;
            let mut warnings = Vec::new();
            if !response.storage_rights {
                warnings.push(SourceWarning::StorageNotPermitted);
            }
            if input_truncated {
                warnings.push(SourceWarning::Truncated);
            }
            let output_cut = response.finish_reason.as_deref() == Some("length");
            if output_cut {
                warnings.push(SourceWarning::PartialExtraction);
            }
            // The raw provider JSON and the generated summary keep distinct
            // identities; the raw response records the model that generated it.
            let evidence = vec![
                Evidence {
                    kind: RepresentationKind::HttpEntity,
                    bytes: response.raw,
                    extraction_version: format!("{name}-chat-json/v1"),
                    derived_from: None,
                    pdf_page: None,
                    text: true,
                },
                Evidence {
                    kind: RepresentationKind::Text,
                    bytes: response.summary.clone().into_bytes(),
                    extraction_version: format!("{name}-summary/v1"),
                    derived_from: Some(0),
                    pdf_page: None,
                    text: true,
                },
            ];
            let saved = self
                .store
                .insert(
                    context.owner,
                    NewSource {
                        job_id: context.job,
                        original_url: subject.clone(),
                        final_url: subject,
                        provider: Some(name.into()),
                        retrieved_at: response.retrieved_at,
                        warnings,
                        evidence,
                    },
                    response.storage_rights,
                )
                .await?;
            let (summary, summary_truncated) = crate::provider::bounded_text(
                &response.summary,
                self.config.limits.result_bytes / 2,
            );
            return Ok(json!({
                "job_id": context.job,
                "state": if input_truncated || output_cut { ItemState::Partial } else { ItemState::Success },
                "input": input,
                "source": SourceBrief::from(&saved),
                "summary_representation": saved.representations.get(1),
                "summary": summary,
                "summary_truncated": summary_truncated,
                "generated": true,
                "provider": name,
                "model": response.model,
                "finish_reason": response.finish_reason,
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "usage": self.read_job(context.owner, context.job).await?.usage,
                "untrusted": true,
                "truncated": false,
            }));
        }
        Err(last)
    }

    async fn read(&self, owner: u32, args: ReadArgs) -> Result<Value> {
        let cap = |requested: Option<usize>| -> Result<usize> {
            let maximum = self.config.limits.result_bytes.saturating_sub(2048);
            let requested = requested.unwrap_or(maximum);
            if requested < 16 || requested > maximum {
                return Err(ErrorCode::InvalidRequest);
            }
            Ok(requested)
        };
        match args {
            ReadArgs::Metadata { source_id } => to_value(self.store.get(owner, source_id).await?),
            ReadArgs::Report {
                report_id,
                start,
                max_bytes,
            } => to_value(
                self.reports
                    .read(owner, report_id, start, cap(max_bytes)?)?,
            ),
            args => {
                let (source, representation, cursor, start, max_bytes) = match args {
                    ReadArgs::Source {
                        source_id,
                        representation_id,
                        cursor,
                        start,
                        max_bytes,
                    } => (source_id, representation_id, cursor, start, max_bytes),
                    ReadArgs::PdfPage {
                        source_id,
                        page,
                        cursor,
                        start,
                        max_bytes,
                    } => {
                        let source = self.store.get(owner, source_id).await?;
                        let representation = source
                            .representations
                            .iter()
                            .find(|rep| rep.pdf_page == Some(page))
                            .ok_or(ErrorCode::NotFound)?
                            .id;
                        (source_id, representation, cursor, start, max_bytes)
                    }
                    _ => return Err(ErrorCode::InvalidRequest),
                };
                if cursor.is_some() && start.is_some() {
                    return Err(ErrorCode::InvalidRequest);
                }
                if let Some(start) = start {
                    to_value(
                        self.store
                            .read_at(owner, source, representation, start, cap(max_bytes)?)
                            .await?,
                    )
                } else {
                    to_value(
                        self.store
                            .read(owner, source, representation, cursor, cap(max_bytes)?)
                            .await?,
                    )
                }
            }
        }
    }
}

fn crawl_page_data(depth: u32, record: &FetchRecord) -> Value {
    let mut links_truncated = record.links.len() > 8;
    let links: Vec<_> = record
        .links
        .iter()
        .take(8)
        .map(|link| {
            let (label, truncated) = crate::provider::bounded_text(&link.label, 512);
            links_truncated |= truncated;
            json!({"url": link.url, "label": label})
        })
        .collect();
    let state = if record.error.is_some()
        || record.source.warnings.iter().any(|warning| {
            matches!(
                warning,
                SourceWarning::PartialExtraction
                    | SourceWarning::Truncated
                    | SourceWarning::JavascriptRequired
                    | SourceWarning::PageShell
                    | SourceWarning::StreamingHtmlRecovered
            )
        }) {
        ItemState::Partial
    } else {
        ItemState::Success
    };
    json!({
        "url": record.source.original_url,
        "final_url": record.source.final_url,
        "depth": depth,
        "state": state,
        "error": record.error,
        "cache_hit": record.cache_hit,
        "title": record.title,
        "source": SourceBrief::from(&record.source),
        "raw_source_id": record.raw_source_id,
        "links": links,
        "links_truncated": links_truncated,
        "javascript_required": record.javascript_hint,
    })
}

fn browser_item(index: usize, result: Result<Value>) -> Item {
    let mut data = match result {
        Ok(data) => data,
        Err(error) => {
            let failure = crate::error::ToolFailure::from(error);
            let mut item = Item::failed(index, failure.code);
            if let Some(details) = failure.details {
                item.data = Some(json!({"error_details": details}));
            }
            return item;
        }
    };
    let error = match serde_json::from_value::<Option<ErrorCode>>(data["error"].clone()) {
        Ok(error) => error,
        Err(_) => return Item::failed(index, ErrorCode::InvalidResponse),
    };
    let partial = error.is_some() || data["partial"] == true;
    data["javascript_required"] = Value::Bool(false);
    Item {
        index,
        state: if partial {
            ItemState::Partial
        } else {
            ItemState::Success
        },
        data: Some(data),
        error,
        duplicate_of: None,
    }
}

enum Work {
    Search(SearchArgs),
    Fetch(FetchArgs),
    Browser(BrowserArgs),
    Summarize {
        job_id: Uuid,
        source_id: Uuid,
        representation_id: Option<Uuid>,
    },
}
impl Work {
    fn job_id(&self) -> Uuid {
        match self {
            Self::Search(args) => args.job_id,
            Self::Fetch(args) => args.job_id,
            Self::Browser(args) => args.job_id(),
            Self::Summarize { job_id, .. } => *job_id,
        }
    }
}
enum Input {
    Search(SearchQuery),
    Fetch(String, FetchMode, Option<CrawlArgs>),
}
impl Input {
    fn key(&self) -> String {
        match self {
            Self::Search(query) => serde_json::to_string(query).expect("serializable query"),
            Self::Fetch(url, _, crawl) => {
                let base = PublicUrl::parse(url)
                    .map(|url| url.request_url().to_string())
                    .unwrap_or_else(|_| url.clone());
                match crawl {
                    Some(crawl) => {
                        format!("{base}|crawl:{}:{}", crawl.pages, crawl.depth)
                    }
                    None => base,
                }
            }
        }
    }
}
fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| ErrorCode::InvalidRequest)
}
fn to_value(value: impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| ErrorCode::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoTransport;

    #[async_trait::async_trait]
    impl Transport for NoTransport {
        async fn get(
            &self,
            _owner: u32,
            _job: Uuid,
            _request: HttpRequest,
            _stop: &CancellationToken,
        ) -> Result<HttpResponse> {
            Err(ErrorCode::ProviderUnavailable)
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<Service>, Arc<Ledger>, u32) {
        let root = tempfile::tempdir().unwrap();
        let owner = rustix::process::getuid().as_raw();
        let config = Config {
            state_directory: root.path().join("state"),
            privacy: Privacy::Strict,
            egress_uid: Some(1002),
            allowed_client_uids: vec![owner],
            ..Config::default()
        };
        std::fs::create_dir_all(&config.state_directory).unwrap();
        let ledger = Ledger::open(
            &config.state_directory.join("budget.sqlite"),
            config.limits.clone(),
        )
        .unwrap();
        let store = EvidenceStore::open(&config, root.path().to_owned()).unwrap();
        let service = Service::new(
            config,
            Dependencies {
                ledger: ledger.clone(),
                store,
                http: Arc::new(NoTransport),
                parser: None,
                search_providers: Vec::new(),
                scrape_providers: Vec::new(),
                summarize_providers: Vec::new(),
            },
        )
        .unwrap();
        (root, service, ledger, owner)
    }

    fn ready() -> EgressState {
        EgressState {
            version: 1,
            generation: Uuid::new_v4(),
            mode: EgressMode::Ready,
            valid_until: chrono::Utc::now().timestamp() + 10,
            region: None,
        }
    }

    fn pending(connection: Uuid) -> Arc<StartingJob> {
        Arc::new(StartingJob {
            connection,
            published: AtomicBool::new(false),
            invalidated: Mutex::new(None),
            stop: CancellationToken::new(),
            done: CancellationToken::new(),
            outcome: Mutex::new(None),
        })
    }

    #[tokio::test]
    async fn pending_starts_reserve_active_job_capacity() {
        let (_root, service, _ledger, owner) = fixture();
        {
            let mut state = service.state.lock().unwrap();
            for _ in 0..service.config.limits.active_jobs {
                state
                    .starting
                    .insert(Uuid::new_v4(), pending(Uuid::new_v4()));
            }
        }
        assert!(matches!(
            service
                .start(
                    owner,
                    Uuid::new_v4(),
                    RequestedLimits::default(),
                    CancellationToken::new(),
                )
                .await,
            Err(ErrorCode::Capacity)
        ));
    }

    #[tokio::test]
    async fn egress_change_invalidates_pending_start_before_waiting_for_cleanup() {
        let (_root, service, _ledger, owner) = fixture();
        service.update_egress(ready()).await.unwrap();
        let ticket = Uuid::new_v4();
        let starting = pending(Uuid::new_v4());
        service
            .state
            .lock()
            .unwrap()
            .starting
            .insert(ticket, starting.clone());
        let next = ready();
        let update = service.update_egress(next.clone());
        tokio::pin!(update);
        assert!(futures_util::poll!(update.as_mut()).is_pending());
        assert_eq!(
            starting.invalidated().unwrap(),
            Some((JobState::Interrupted, ErrorCode::EgressChanged))
        );
        assert!(starting.stop.is_cancelled());
        assert_eq!(
            service.readiness(owner).unwrap()["egress"]["generation"],
            serde_json::json!(next.generation)
        );
        service.state.lock().unwrap().starting.remove(&ticket);
        starting.complete(Ok(()));
        update.await.unwrap();
    }

    #[test]
    fn start_reconciles_after_the_callers_runtime_is_destroyed() {
        let (root, service, _ledger, owner) = fixture();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        *service.start_hook.lock().unwrap() = Some(Arc::new(move || {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        }));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(service.update_egress(ready())).unwrap();
        let start = runtime.spawn({
            let service = service.clone();
            async move {
                service
                    .start(
                        owner,
                        Uuid::new_v4(),
                        RequestedLimits::default(),
                        CancellationToken::new(),
                    )
                    .await
            }
        });
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if entered_rx.try_recv().is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        });
        let starting = service
            .state
            .lock()
            .unwrap()
            .starting
            .values()
            .next()
            .unwrap()
            .clone();
        runtime.shutdown_background();
        drop(start);
        *service.start_hook.lock().unwrap() = None;

        let next_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        next_runtime.block_on(async {
            let update = service.update_egress(ready());
            tokio::pin!(update);
            assert!(futures_util::poll!(update.as_mut()).is_pending());
            assert_eq!(
                starting.invalidated().unwrap(),
                Some((JobState::Interrupted, ErrorCode::EgressChanged))
            );
            release_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), update)
                .await
                .unwrap()
                .unwrap();
            assert!(service.state.lock().unwrap().starting.is_empty());
            assert!(service.state.lock().unwrap().jobs.is_empty());
            let connection =
                rusqlite::Connection::open(root.path().join("state/budget.sqlite")).unwrap();
            let states: Vec<String> = connection
                .prepare("SELECT state FROM jobs")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            assert_eq!(states, vec!["interrupted"]);

            let job = service
                .start(
                    owner,
                    Uuid::new_v4(),
                    RequestedLimits::default(),
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            service
                .close_job(owner, job.id, JobState::Cancelled)
                .await
                .unwrap();
        });
    }

    #[tokio::test]
    async fn egress_cleanup_supervisor_deduplicates_and_reports_failure() {
        let (_root, service, _ledger, _owner) = fixture();
        let mut cleanup = CleanupSupervisor::new(service.limits().active_jobs);
        service.observe_egress(ready(), &mut cleanup).unwrap();
        let ticket = Uuid::new_v4();
        let starting = pending(Uuid::new_v4());
        service
            .state
            .lock()
            .unwrap()
            .starting
            .insert(ticket, starting.clone());
        for _ in 0..128 {
            service.observe_egress(ready(), &mut cleanup).unwrap();
            assert_eq!(cleanup.tasks.len(), 1);
            assert_eq!(cleanup.starts.len(), 1);
        }
        service.state.lock().unwrap().starting.remove(&ticket);
        starting.complete(Err(ErrorCode::Storage));
        assert_eq!(cleanup.next().await, Err(ErrorCode::Storage));
        assert!(cleanup.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rpc_observes_offline_and_accepts_while_start_cleanup_stalls() {
        use crate::protocol::{Operation, Outcome, Request, Response, VERSION};
        use tokio::net::{UnixListener, UnixStream};

        let (root, service, _ledger, owner) = fixture();
        let socket_path = root.path().join("rpc.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let first = ready();
        let control = Arc::new(Mutex::new(Ok(first.clone())));
        let stop = CancellationToken::new();
        let serving = tokio::spawn({
            let service = service.clone();
            let control = control.clone();
            let stop = stop.clone();
            async move {
                crate::rpc::serve_with_control(
                    listener,
                    service,
                    std::path::Path::new("synthetic"),
                    stop,
                    move |_| control.lock().unwrap().clone(),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while service.readiness(owner).unwrap()["egress"]["generation"]
                != json!(first.generation)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();

        let ticket = Uuid::new_v4();
        let starting = pending(Uuid::new_v4());
        service
            .state
            .lock()
            .unwrap()
            .starting
            .insert(ticket, starting.clone());
        let second = ready();
        *control.lock().unwrap() = Ok(second.clone());
        tokio::time::timeout(Duration::from_secs(3), async {
            while service.readiness(owner).unwrap()["egress"]["generation"]
                != json!(second.generation)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(starting.stop.is_cancelled());
        assert!(!starting.done.is_cancelled());

        let mut socket = UnixStream::connect(&socket_path).await.unwrap();
        crate::protocol::write_frame(
            &mut socket,
            &Request {
                version: VERSION,
                id: 1,
                operation: Operation::Hello,
            },
        )
        .await
        .unwrap();
        let hello = tokio::time::timeout(
            Duration::from_secs(3),
            crate::protocol::read_frame::<_, Response>(&mut socket),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(matches!(hello.outcome, Outcome::Result { .. }));

        *control.lock().unwrap() = Err(crate::egress::LeaseReadError::Unavailable);
        tokio::time::timeout(Duration::from_secs(3), async {
            while service.readiness(owner).unwrap()["egress"]["mode"] != json!("offline") {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        crate::protocol::write_frame(
            &mut socket,
            &Request {
                version: VERSION,
                id: 2,
                operation: Operation::Call {
                    tool: Tool::ResearchJob,
                    arguments: json!({"operation":"readiness"}),
                },
            },
        )
        .await
        .unwrap();
        let readiness = tokio::time::timeout(
            Duration::from_secs(3),
            crate::protocol::read_frame::<_, Response>(&mut socket),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        match readiness.outcome {
            Outcome::Result { value } => {
                assert_eq!(value["egress"]["mode"], json!("offline"));
                assert_eq!(value["egress"]["lease_valid"], json!(false));
            }
            other => panic!("unexpected readiness response: {other:?}"),
        }

        stop.cancel();
        tokio::time::timeout(Duration::from_secs(3), async {
            while service.readiness(owner).unwrap()["accepting"] != json!(false) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!serving.is_finished());
        assert!(!starting.done.is_cancelled());
        service.state.lock().unwrap().starting.remove(&ticket);
        starting.complete(Ok(()));
        drop(socket);
        tokio::time::timeout(Duration::from_secs(3), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn disconnect_invalidates_only_its_pending_starts_and_waits_for_them() {
        let (_root, service, _ledger, _owner) = fixture();
        let connection = Uuid::new_v4();
        let ticket = Uuid::new_v4();
        let starting = pending(connection);
        let other = pending(Uuid::new_v4());
        {
            let mut state = service.state.lock().unwrap();
            state.starting.insert(ticket, starting.clone());
            state.starting.insert(Uuid::new_v4(), other.clone());
        }
        let disconnect = service.disconnect(connection);
        tokio::pin!(disconnect);
        assert!(futures_util::poll!(disconnect.as_mut()).is_pending());
        assert_eq!(
            starting.invalidated().unwrap(),
            Some((JobState::Cancelled, ErrorCode::Cancelled))
        );
        assert!(!other.stop.is_cancelled());
        service.state.lock().unwrap().starting.remove(&ticket);
        starting.complete(Ok(()));
        disconnect.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_waits_for_pending_cleanup_and_propagates_failure() {
        let (_root, service, _ledger, owner) = fixture();
        let ticket = Uuid::new_v4();
        let starting = pending(Uuid::new_v4());
        service
            .state
            .lock()
            .unwrap()
            .starting
            .insert(ticket, starting.clone());
        let shutdown = service.shutdown();
        tokio::pin!(shutdown);
        assert!(futures_util::poll!(shutdown.as_mut()).is_pending());
        assert_eq!(
            starting.invalidated().unwrap(),
            Some((JobState::Interrupted, ErrorCode::Cancelled))
        );
        assert!(matches!(
            service
                .start(
                    owner,
                    Uuid::new_v4(),
                    RequestedLimits::default(),
                    CancellationToken::new()
                )
                .await,
            Err(ErrorCode::Cancelled)
        ));
        service.state.lock().unwrap().starting.remove(&ticket);
        starting.complete(Err(ErrorCode::Storage));
        assert_eq!(shutdown.await, Err(ErrorCode::Storage));
    }

    #[tokio::test]
    async fn dropped_close_still_drains_activity_before_terminal_accounting() {
        let (_root, service, ledger, owner) = fixture();
        service.update_egress(ready()).await.unwrap();
        let job = service
            .start(
                owner,
                Uuid::new_v4(),
                RequestedLimits::default(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let id = job.id;
        let (lease, _) = service
            .admit(owner, id, &CancellationToken::new())
            .await
            .unwrap();
        let running = lease.0.clone();
        let closer = {
            let service = service.clone();
            tokio::spawn(async move { service.close_job(owner, id, JobState::Cancelled).await })
        };
        running.stop.cancelled().await;
        assert_eq!(ledger.get(owner, id).unwrap().state, JobState::Active);
        assert!(matches!(
            service.admit(owner, id, &CancellationToken::new()).await,
            Err(ErrorCode::JobClosed)
        ));
        closer.abort();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !service.state.lock().unwrap().jobs.contains_key(&id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ledger.get(owner, id).unwrap().state, JobState::Cancelled);
    }
}
