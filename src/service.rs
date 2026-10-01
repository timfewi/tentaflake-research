//! Job ownership, cooperative cancellation and the five tool implementations.
//! Cancellation always waits for the operation to release its worker/IO leases.

use crate::api::*;
use crate::archive::{Evidence, NewSource, RepresentationKind, SourceWarning};
use crate::browser::profile::Profile;
use crate::budget::{Job, JobState, Ledger, RequestedLimits};
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
use tokio::sync::{Notify, Semaphore};
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
    accepting: bool,
    egress: EgressState,
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
                accepting: true,
                egress: EgressState::offline(),
            }),
            crawl_pacing: Mutex::new(HashMap::new()),
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

    fn start(&self, owner: u32, connection: Uuid, limits: RequestedLimits) -> Result<Job> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        if !state.accepting {
            return Err(ErrorCode::Cancelled);
        }
        if state.jobs.len() >= self.config.limits.active_jobs {
            return Err(ErrorCode::Capacity);
        }
        let job = self.ledger.start(owner, limits)?;
        state.jobs.insert(
            job.id,
            Arc::new(RunningJob {
                owner,
                connection,
                deadline: Instant::now() + Duration::from_secs(job.limits.seconds),
                stop: CancellationToken::new(),
                activity: Mutex::new(Activity {
                    closed: false,
                    count: 0,
                    error: None,
                }),
                changed: Notify::new(),
                closing: tokio::sync::Mutex::new(()),
            }),
        );
        Ok(job)
    }

    fn admit(&self, owner: u32, id: Uuid) -> Result<(OperationLease, Context)> {
        let state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
        if !state.accepting {
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
        let mut activity = job.activity.lock().map_err(|_| ErrorCode::Storage)?;
        if activity.closed
            || job.stop.is_cancelled()
            || Instant::now() >= job.deadline
            || self.ledger.get(owner, id)?.state != JobState::Active
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

    pub async fn close_job(&self, owner: u32, id: Uuid, reason: JobState) -> Result<Job> {
        let job = self
            .state
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .jobs
            .get(&id)
            .filter(|job| job.owner == owner)
            .cloned();
        let Some(job) = job else {
            return self.ledger.get(owner, id);
        };
        // Concurrent cancel/finish/disconnect callers all observe completed cleanup.
        let _closing = job.closing.lock().await;
        {
            let mut activity = job.activity.lock().map_err(|_| ErrorCode::Storage)?;
            activity.closed = true;
            activity.error.get_or_insert(match reason {
                JobState::Interrupted => ErrorCode::EgressChanged,
                JobState::Expired => ErrorCode::Timeout,
                _ => ErrorCode::Cancelled,
            });
        }
        job.stop.cancel();
        self.ledger.end(owner, id, reason)?;
        loop {
            let changed = job.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if job.activity.lock().map_err(|_| ErrorCode::Storage)?.count == 0 {
                break;
            }
            changed.await;
        }
        if let Some(browser) = &self.browser {
            browser.finish_job(owner, id).await?;
        }
        self.fetcher.finish_job(owner, id)?;
        self.searches.remove_job(owner, id)?;
        self.store.finish_job(owner, id)?;
        self.reports.finish_job(owner, id)?;
        self.state
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .jobs
            .remove(&id);
        self.ledger.get(owner, id)
    }

    pub async fn disconnect(&self, connection: Uuid) -> Result<()> {
        let jobs: Vec<_> = self
            .state
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .jobs
            .iter()
            .filter(|(_, job)| job.connection == connection)
            .map(|(id, job)| (job.owner, *id))
            .collect();
        for (owner, id) in jobs {
            self.close_job(owner, id, JobState::Cancelled).await?;
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        let jobs: Vec<_> = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::Storage)?;
            state.accepting = false;
            state
                .jobs
                .iter()
                .map(|(id, job)| (job.owner, *id))
                .collect()
        };
        for (owner, id) in jobs {
            self.close_job(owner, id, JobState::Interrupted).await?;
        }
        self.store.maintenance().await
    }

    /// Ready/Draining/Offline comes only from the root-owned, short-lived lease.
    /// Draining pauses admission; loss or a new exit generation interrupts jobs.
    pub async fn update_egress(&self, next: EgressState) -> Result<()> {
        let jobs: Vec<_> = {
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
            if interrupt {
                state
                    .jobs
                    .iter()
                    .map(|(id, job)| (job.owner, *id))
                    .collect()
            } else {
                Vec::new()
            }
        };
        for (owner, id) in jobs {
            self.close_job(owner, id, JobState::Interrupted).await?;
        }
        Ok(())
    }

    pub async fn expire(&self) -> Result<()> {
        let jobs: Vec<_> = self
            .state
            .lock()
            .map_err(|_| ErrorCode::Storage)?
            .jobs
            .iter()
            .filter(|(_, job)| Instant::now() >= job.deadline)
            .map(|(id, job)| (job.owner, *id))
            .collect();
        for (owner, id) in jobs {
            self.close_job(owner, id, JobState::Expired).await?;
        }
        Ok(())
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
        &self,
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
        let (scope, value) = match tool {
            Tool::ResearchJob => {
                let args: JobArgs = parse(arguments)?;
                let (job, include_sources) = match args {
                    JobArgs::Start { limits } => (self.start(owner, connection, limits)?, false),
                    JobArgs::Status { job_id } => (self.ledger.get(owner, job_id)?, true),
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
        let (lease, context) = self.admit(owner, work.job_id())?;
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
                result["usage"] = to_value(self.ledger.get(context.owner, context.job)?.usage)?;
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
            "usage":self.ledger.get(context.owner, context.job)?.usage,"untrusted":true,"truncated":false}),
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
                self.crawl_seed(context, &target, &record.links, crawl)
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
            if let Some(data) = rendered.data.as_mut() {
                data["http"] = item.data.take().expect("HTTP evidence was assembled above");
                rendered
            } else {
                item.state = ItemState::Partial;
                item.error = rendered.error;
                if let Some(data) = item.data.as_mut() {
                    data["render_error"] = json!(rendered.error);
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
                "usage": self.ledger.get(context.owner, context.job)?.usage,
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
                "usage": self.ledger.get(context.owner, context.job)?.usage,
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
        Err(error) => return Item::failed(index, error),
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
