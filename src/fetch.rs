//! Selected-page retrieval: robots, redirects, retries, raw evidence, then
//! authorized parser work. A parser failure keeps the already archived response.

use crate::archive::{Evidence, NewSource, RepresentationKind, Source, SourceWarning};
use crate::budget::{Charge, Ledger};
use crate::cache::{Cache, Key};
use crate::config::{Config, MAX_HTTP_BODY_BYTES, MAX_PDF_PAGES, Privacy};
use crate::error::{ErrorCode, Result};
use crate::http::{HttpRequest, HttpResponse, Transport, retry_after_headers};
use crate::policy::{PublicUrl, sha256};
use crate::provider::Context;
use crate::robots::{AccessKind, RobotsDocument};
use crate::store::EvidenceStore;
use crate::worker::{self, DocumentKind, ExtractionInput, ParsedDocument, PdfInfo, WorkerConfig};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

#[async_trait::async_trait]
pub trait Parser: Send + Sync {
    async fn inspect(&self, context: &Context, input: ExtractionInput<'_>) -> Result<PdfInfo>;
    async fn extract(
        &self,
        context: &Context,
        input: ExtractionInput<'_>,
    ) -> Result<ParsedDocument>;
}

pub struct IsolatedParser {
    config: WorkerConfig,
    temporary: PathBuf,
    slots: Arc<Semaphore>,
}

struct OwnedExtractionInput {
    bytes: Vec<u8>,
    kind: DocumentKind,
    base: PublicUrl,
    content_type: String,
    max_pages: u32,
}

impl OwnedExtractionInput {
    fn new(input: ExtractionInput<'_>) -> Result<Self> {
        // Bound the copy before detaching work from its caller.
        if input.bytes.len() as u64 > MAX_HTTP_BODY_BYTES
            || input.content_type.len() > 256
            || input.max_pages == 0
            || input.max_pages > MAX_PDF_PAGES
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            bytes: input.bytes.to_vec(),
            kind: input.kind,
            base: input.base.clone(),
            content_type: input.content_type.to_owned(),
            max_pages: input.max_pages,
        })
    }

    fn borrowed(&self) -> ExtractionInput<'_> {
        ExtractionInput {
            bytes: &self.bytes,
            kind: self.kind,
            base: &self.base,
            content_type: &self.content_type,
            max_pages: self.max_pages,
        }
    }
}

enum ParserTask {
    Inspect,
    Extract,
}

enum ParserValue {
    Info(PdfInfo),
    Document(ParsedDocument),
}

/// A task that panics or loses its scratch cleanup must not free capacity.
struct ParserPermit(Option<OwnedSemaphorePermit>);

impl ParserPermit {
    fn release(mut self) {
        drop(self.0.take());
    }
}

impl Drop for ParserPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.0.take() {
            permit.forget();
        }
    }
}

impl IsolatedParser {
    pub fn new(config: WorkerConfig, temporary: PathBuf, concurrency: usize) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            temporary,
            slots: Arc::new(Semaphore::new(concurrency.max(1))),
        })
    }

    async fn run(
        &self,
        context: &Context,
        input: ExtractionInput<'_>,
        operation: ParserTask,
    ) -> Result<ParserValue> {
        let acquired = tokio::select! {
            biased;
            _ = context.stop.cancelled() => return Err(ErrorCode::Cancelled),
            permit = self.slots.clone().acquire_owned() => permit.map_err(|_| ErrorCode::Cancelled)?,
        };
        let input = OwnedExtractionInput::new(input)?;
        let permit = ParserPermit(Some(acquired));
        let config = self.config.clone();
        let temporary = self.temporary.clone();
        // The caller may disappear while the worker is running. Its drop guard
        // requests cancellation; this independent task still reaps the worker,
        // removes scratch, and only then releases the parser slot.
        let stop = context.stop.child_token();
        let _cancel_on_drop = stop.clone().drop_guard();
        tokio::spawn(async move {
            let mut cleanup_failed = false;
            let result = match operation {
                ParserTask::Inspect => worker::inspect_pdf_tracked(
                    &config,
                    &temporary,
                    input.borrowed(),
                    &stop,
                    &mut cleanup_failed,
                )
                .await
                .map(ParserValue::Info),
                ParserTask::Extract => worker::extract_tracked(
                    &config,
                    &temporary,
                    input.borrowed(),
                    &stop,
                    &mut cleanup_failed,
                )
                .await
                .map(ParserValue::Document),
            };
            if !cleanup_failed {
                permit.release();
            }
            result
        })
        .await
        .map_err(|_| ErrorCode::WorkerFailed)?
    }
}

#[async_trait::async_trait]
impl Parser for IsolatedParser {
    async fn inspect(&self, context: &Context, input: ExtractionInput<'_>) -> Result<PdfInfo> {
        match self.run(context, input, ParserTask::Inspect).await? {
            ParserValue::Info(info) => Ok(info),
            ParserValue::Document(_) => Err(ErrorCode::WorkerFailed),
        }
    }
    async fn extract(
        &self,
        context: &Context,
        input: ExtractionInput<'_>,
    ) -> Result<ParsedDocument> {
        match self.run(context, input, ParserTask::Extract).await? {
            ParserValue::Document(document) => Ok(document),
            ParserValue::Info(_) => Err(ErrorCode::WorkerFailed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRecord {
    pub source: Source,
    pub raw_source_id: uuid::Uuid,
    pub title: String,
    pub links: Vec<worker::Link>,
    pub error: Option<ErrorCode>,
    pub cache_hit: bool,
    pub javascript_hint: bool,
}

/// One browser HTTP entity, retained before access/error handling. It is never
/// presented as rendered DOM; even a denied/error response has its own identity.
pub struct BrowserEntity {
    pub source: Source,
    pub response: HttpResponse,
    pub error: Option<ErrorCode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedRecord {
    pub source: Source,
    pub dom_source_id: uuid::Uuid,
    pub links: Vec<worker::Link>,
    pub error: Option<ErrorCode>,
}

/// Result of the discovery robots check for a page reached by crawling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryDecision {
    /// Robots permits fetching this discovered page.
    Allowed,
    /// A valid disallow or access block applies; skip only this page.
    Skip,
    /// Robots is unavailable/throttled; stop discovering further pages.
    Pause,
}

pub struct Fetcher {
    config: Config,
    policy: String,
    http: Arc<dyn Transport>,
    parser: Option<Arc<dyn Parser>>,
    ledger: Arc<Ledger>,
    store: Arc<EvidenceStore>,
    robots: Cache<RobotsDocument>,
    documents: Cache<FetchRecord>,
}

impl Fetcher {
    pub fn new(
        config: Config,
        http: Arc<dyn Transport>,
        parser: Option<Arc<dyn Parser>>,
        ledger: Arc<Ledger>,
        store: Arc<EvidenceStore>,
    ) -> Result<Self> {
        let policy = sha256(&serde_json::to_vec(&config).map_err(|_| ErrorCode::InvalidRequest)?);
        Ok(Self {
            config,
            policy,
            http,
            parser,
            ledger,
            store,
            robots: Cache::new(256, 8 * 1024 * 1024)?,
            documents: Cache::new(512, 16 * 1024 * 1024)?,
        })
    }

    fn key(&self, context: &Context, input: &str) -> Result<Key> {
        Key::new(
            context.owner,
            (self.config.privacy == Privacy::Strict).then_some(context.job),
            &self.policy,
            &input,
        )
    }

    pub fn finish_job(&self, owner: u32, job: uuid::Uuid) -> Result<()> {
        self.robots.remove_job(owner, job)?;
        self.documents.remove_job(owner, job)
    }

    pub fn maintenance(&self) -> Result<()> {
        self.robots.maintenance()?;
        self.documents.maintenance()
    }

    pub async fn browser_entity(
        &self,
        context: &Context,
        input: crate::browser::wire::HttpRequest,
    ) -> Result<BrowserEntity> {
        use crate::browser::request;
        if context.stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        if Instant::now() >= context.deadline {
            return Err(ErrorCode::Timeout);
        }
        let checked = request::check(&input, &self.config.browser.read_post_rules)?;
        if input.redirects as usize > self.config.limits.redirects {
            return Err(ErrorCode::SizeLimit);
        }
        if input.main_document && input.redirects == 0 {
            self.ledger
                .reserve(
                    context.owner,
                    context.job,
                    Charge {
                        documents: 1,
                        ..Charge::default()
                    },
                )?
                .finish(0, Some(0))?;
        }
        let warnings = if self.allowed(context, &checked.target).await? {
            vec![SourceWarning::RobotsUnavailable]
        } else {
            vec![]
        };
        let mut attempt = 0;
        let response = loop {
            let response = self
                .http
                .browser(
                    context.owner,
                    context.job,
                    crate::http::BrowserRequest {
                        request: input.clone(),
                        rules: &self.config.browser.read_post_rules,
                        max_bytes: if checked.method == reqwest::Method::OPTIONS {
                            crate::browser::request::MAX_PREFLIGHT_RESPONSE_BYTES.min(
                                self.config
                                    .limits
                                    .pdf_bytes
                                    .max(self.config.limits.html_bytes),
                            )
                        } else {
                            self.config.limits.pdf_bytes
                        },
                    },
                    &context.stop,
                )
                .await;
            // Exact reviewed POST requests are admitted, but are not replayed
            // automatically after an uncertain result.
            let delay = (checked.method != reqwest::Method::POST
                && checked.method != reqwest::Method::OPTIONS
                && attempt < self.config.limits.retries)
                .then(|| {
                    retry_delay(
                        &response,
                        attempt,
                        context.deadline.saturating_duration_since(Instant::now()),
                    )
                })
                .flatten();
            let Some(delay) = delay else {
                break response?;
            };
            tokio::select! { biased;
                _ = context.stop.cancelled() => return Err(ErrorCode::Cancelled),
                _ = tokio::time::sleep(delay) => (),
            }
            attempt += 1;
        };
        let source = self
            .store
            .insert(
                context.owner,
                NewSource {
                    job_id: context.job,
                    original_url: checked.target.clone(),
                    final_url: checked.target.clone(),
                    provider: None,
                    retrieved_at: chrono::Utc::now().timestamp(),
                    warnings,
                    evidence: vec![raw(&response.body)],
                },
                true,
            )
            .await?;
        let error = if checked.method == reqwest::Method::OPTIONS
            && !(200..=299).contains(&response.status)
        {
            Some(ErrorCode::AccessBlocked)
        } else {
            browser_status(&response, &checked.target, input.redirects, &self.config).err()
        };
        Ok(BrowserEntity {
            source,
            response,
            error,
        })
    }

    /// Store DOM first, then isolated extraction. A parser failure cannot erase
    /// the observed DOM or replace its identity with an original HTTP entity.
    pub async fn rendered(
        &self,
        context: &Context,
        original: &PublicUrl,
        snapshot: &crate::browser::read::PageSnapshot,
    ) -> Result<RenderedRecord> {
        snapshot.metadata.validate(self.config.limits.html_bytes)?;
        if snapshot.html.len() as u64 != snapshot.metadata.html_bytes
            || sha256(&snapshot.html) != snapshot.metadata.html_sha256
        {
            return Err(ErrorCode::InvalidResponse);
        }
        let reservation = self.ledger.reserve(
            context.owner,
            context.job,
            Charge {
                bytes: snapshot.html.len() as u64,
                ..Charge::default()
            },
        )?;
        reservation.finish(snapshot.html.len() as u64, Some(0))?;
        let target = PublicUrl::parse(&snapshot.metadata.url)?;
        let retrieved_at = chrono::Utc::now().timestamp();
        let mut warnings = Vec::new();
        if snapshot.metadata.truncated_references {
            warnings.push(SourceWarning::Truncated);
        }
        if snapshot.metadata.pending_requests || !snapshot.metadata.request_errors.is_empty() {
            warnings.push(SourceWarning::PartialExtraction);
        }
        let dom = || Evidence {
            kind: RepresentationKind::RenderedDom,
            bytes: snapshot.html.clone(),
            extraction_version: "chromium/dom-outer-html/v1".into(),
            derived_from: None,
            pdf_page: None,
            text: true,
        };
        let input = |evidence, warnings| NewSource {
            job_id: context.job,
            original_url: original.clone(),
            final_url: target.clone(),
            provider: None,
            retrieved_at,
            warnings,
            evidence,
        };
        let source = self
            .store
            .insert(context.owner, input(vec![dom()], warnings.clone()), true)
            .await?;
        let mut record = RenderedRecord {
            dom_source_id: source.id,
            source,
            links: vec![],
            error: None,
        };
        let extraction = async {
            let parser = self.parser.as_ref().ok_or(ErrorCode::ProviderUnavailable)?;
            if context.stop.is_cancelled() {
                return Err(ErrorCode::Cancelled);
            }
            parser
                .extract(
                    context,
                    ExtractionInput {
                        bytes: &snapshot.html,
                        kind: DocumentKind::Html,
                        base: &target,
                        content_type: "text/html; charset=utf-8",
                        max_pages: self.config.limits.pdf_pages,
                    },
                )
                .await
        }
        .await;
        match extraction {
            Err(error) => record.error = Some(error),
            Ok(parsed) => {
                let mut evidence = vec![dom()];
                extraction_warnings(&parsed.warnings, &mut warnings, true);
                if !parsed.links.is_empty() {
                    evidence.push(Evidence {
                        kind: RepresentationKind::Links,
                        bytes: serde_json::to_vec(&parsed.links)
                            .map_err(|_| ErrorCode::ExtractionFailed)?,
                        extraction_version: "research-links/v1".into(),
                        derived_from: Some(0),
                        pdf_page: None,
                        text: true,
                    });
                }
                record.links = parsed.links;
                for page in parsed.pages {
                    evidence.push(Evidence {
                        kind: RepresentationKind::Text,
                        bytes: page.into_bytes(),
                        extraction_version: parsed.extraction_version.clone(),
                        derived_from: Some(0),
                        pdf_page: None,
                        text: true,
                    });
                }
                if let Some(readable) = parsed.readable_text {
                    evidence.push(Evidence {
                        kind: RepresentationKind::Text,
                        bytes: readable.into_bytes(),
                        extraction_version: "dom_smoothie/0.18.0;raw-text".into(),
                        derived_from: Some(0),
                        pdf_page: None,
                        text: true,
                    });
                }
                match self
                    .store
                    .insert(context.owner, input(evidence, warnings), true)
                    .await
                {
                    Ok(source) => record.source = source,
                    Err(error) => record.error = Some(error),
                }
            }
        }
        Ok(record)
    }

    pub async fn fetch(&self, context: &Context, target: &PublicUrl) -> Result<FetchRecord> {
        if context.stop.is_cancelled() {
            return Err(ErrorCode::Cancelled);
        }
        // Fragments are resolved by the client, not the HTTP server. Strip them
        // before caching and archiving so one request cannot expose another's
        // client-only fragment through a shared cached source.
        let target = target.without_fragment();
        self.ledger
            .reserve(
                context.owner,
                context.job,
                Charge {
                    documents: 1,
                    ..Charge::default()
                },
            )?
            .finish(0, Some(0))?;
        let key = self.key(context, target.as_str())?;
        // An archive may evict evidence earlier than the HTTP freshness window.
        // Retry initialization once after invalidation, without returning dead IDs.
        for _ in 0..2 {
            let (value, hit) = self
                .documents
                .get_or_init_cancellable(key.clone(), &context.stop, || async {
                    let (record, ttl) = self.uncached(context, &target).await?;
                    let weight = serde_json::to_vec(&record)
                        .map_err(|_| ErrorCode::Storage)?
                        .len();
                    Ok((record, ttl, weight))
                })
                .await?;
            if self.store.get(context.owner, value.source.id).await.is_ok() {
                let mut record = (*value).clone();
                record.cache_hit = hit;
                return Ok(record);
            }
            self.documents.invalidate(&key)?;
        }
        Err(ErrorCode::SourceExpired)
    }

    async fn uncached(
        &self,
        context: &Context,
        original: &PublicUrl,
    ) -> Result<(FetchRecord, Duration)> {
        let mut target = original.clone();
        let mut seen = HashSet::new();
        let mut warnings = Vec::new();
        let mut final_response = None;
        for redirect in 0..=self.config.limits.redirects {
            if !seen.insert(target.request_url().to_string()) {
                return Err(ErrorCode::InvalidResponse);
            }
            if self.allowed(context, &target).await?
                && !warnings
                    .iter()
                    .any(|w| matches!(w, SourceWarning::RobotsUnavailable))
            {
                warnings.push(SourceWarning::RobotsUnavailable);
            }
            let response = self
                .read_attempts(context, &target, self.config.limits.pdf_bytes)
                .await?;
            if [301, 302, 303, 307, 308].contains(&response.status) {
                if redirect == self.config.limits.redirects {
                    return Err(ErrorCode::SizeLimit);
                }
                let location = response
                    .headers
                    .get("location")
                    .ok_or(ErrorCode::InvalidResponse)?
                    .to_str()
                    .map_err(|_| ErrorCode::InvalidResponse)?;
                target = target.redirect(location)?.without_fragment();
            } else {
                final_response = Some(response);
                break;
            }
        }
        let response = final_response.ok_or(ErrorCode::InvalidResponse)?;
        let retrieved_at = chrono::Utc::now().timestamp();
        let raw_source = self
            .store
            .insert(
                context.owner,
                NewSource {
                    job_id: context.job,
                    original_url: original.clone(),
                    final_url: target.clone(),
                    provider: None,
                    retrieved_at,
                    warnings: warnings.clone(),
                    evidence: vec![raw(&response.body)],
                },
                true,
            )
            .await?;
        let mut record = FetchRecord {
            source: raw_source.clone(),
            raw_source_id: raw_source.id,
            title: String::new(),
            links: vec![],
            error: None,
            cache_hit: false,
            javascript_hint: false,
        };
        let processed = self.process(context, &target, &response).await;
        match processed {
            Ok((kind, parsed)) => {
                record.title = parsed.title;
                record.links = parsed.links;
                record.javascript_hint = matches!(kind, DocumentKind::Html)
                    && parsed
                        .warnings
                        .contains(&crate::worker::ExtractionWarning::JavascriptRequired);
                if record.javascript_hint {
                    warnings.push(SourceWarning::JavascriptRequired);
                }
                extraction_warnings(&parsed.warnings, &mut warnings, false);
                let mut evidence = vec![raw(&response.body)];
                if !record.links.is_empty() {
                    evidence.push(Evidence {
                        kind: RepresentationKind::Links,
                        bytes: serde_json::to_vec(&record.links)
                            .map_err(|_| ErrorCode::ExtractionFailed)?,
                        extraction_version: "research-links/v1".into(),
                        derived_from: Some(0),
                        pdf_page: None,
                        text: true,
                    });
                }
                for (index, page) in parsed.pages.into_iter().enumerate() {
                    evidence.push(Evidence {
                        kind: if matches!(kind, DocumentKind::Pdf) {
                            RepresentationKind::PdfPageText
                        } else {
                            RepresentationKind::Text
                        },
                        bytes: page.into_bytes(),
                        extraction_version: parsed.extraction_version.clone(),
                        derived_from: Some(0),
                        pdf_page: matches!(kind, DocumentKind::Pdf).then_some(index as u32 + 1),
                        text: true,
                    });
                }
                if let Some(readable) = parsed.readable_text {
                    evidence.push(Evidence {
                        kind: RepresentationKind::Text,
                        bytes: readable.into_bytes(),
                        extraction_version: "dom_smoothie/0.18.0;raw-text".into(),
                        derived_from: Some(0),
                        pdf_page: None,
                        text: true,
                    });
                }
                match self
                    .store
                    .insert(
                        context.owner,
                        NewSource {
                            job_id: context.job,
                            original_url: original.clone(),
                            final_url: target,
                            provider: None,
                            retrieved_at,
                            warnings,
                            evidence,
                        },
                        true,
                    )
                    .await
                {
                    Ok(source) => record.source = source,
                    Err(error) => record.error = Some(error),
                }
            }
            Err(error) => record.error = Some(error),
        }
        let ttl = if record.error.is_some() {
            Duration::ZERO
        } else {
            cache_ttl(&response.headers, self.config.retention.cache_seconds)
        };
        Ok((record, ttl))
    }

    async fn process(
        &self,
        context: &Context,
        target: &PublicUrl,
        response: &HttpResponse,
    ) -> Result<(DocumentKind, ParsedDocument)> {
        match response.status {
            // Selected pages are unranged GETs. A partial or delta-coded
            // response must not become a complete document or curl body.
            206 | 226 => return Err(ErrorCode::InvalidResponse),
            200..=299 => (),
            401 | 403 | 407 | 451 => return Err(ErrorCode::AccessBlocked),
            404 | 410 => return Err(ErrorCode::NotFound),
            429 => return Err(ErrorCode::RateLimited),
            _ => return Err(ErrorCode::InvalidResponse),
        }
        if response
            .headers
            .get("cf-mitigated")
            .is_some_and(|h| h == "challenge")
        {
            return Err(ErrorCode::AccessBlocked);
        }
        let content_type = response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream");
        let media = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let kind = if response.body.starts_with(b"%PDF-") || media == "application/pdf" {
            DocumentKind::Pdf
        } else if matches!(media.as_str(), "text/html" | "application/xhtml+xml") {
            DocumentKind::Html
        } else if media.starts_with("text/")
            || matches!(media.as_str(), "application/json" | "application/xml")
        {
            DocumentKind::Text
        } else {
            return Err(ErrorCode::ExtractionFailed);
        };
        if !matches!(kind, DocumentKind::Pdf)
            && response.body.len() as u64 > self.config.limits.html_bytes
        {
            return Err(ErrorCode::SizeLimit);
        }
        let parser = self.parser.as_ref().ok_or(ErrorCode::ProviderUnavailable)?;
        let input = || ExtractionInput {
            bytes: &response.body,
            kind,
            base: target,
            content_type,
            max_pages: self.config.limits.pdf_pages,
        };
        if matches!(kind, DocumentKind::Pdf) {
            let info = parser.inspect(context, input()).await?;
            self.ledger
                .reserve(
                    context.owner,
                    context.job,
                    Charge {
                        pdf_pages: info.pages,
                        ..Charge::default()
                    },
                )?
                .finish(0, Some(0))?;
            let parsed = parser
                .extract(
                    context,
                    ExtractionInput {
                        max_pages: info.pages,
                        ..input()
                    },
                )
                .await?;
            if parsed.pages.len() != info.pages as usize {
                return Err(ErrorCode::InvalidResponse);
            }
            Ok((kind, parsed))
        } else {
            Ok((kind, parser.extract(context, input()).await?))
        }
    }

    async fn allowed(&self, context: &Context, target: &PublicUrl) -> Result<bool> {
        self.allowed_kind(context, target, AccessKind::SelectedPage)
            .await
    }

    async fn allowed_kind(
        &self,
        context: &Context,
        target: &PublicUrl,
        kind: AccessKind,
    ) -> Result<bool> {
        let document = self.robots_for(context, target).await?;
        Ok(document
            .decide(target, kind, self.config.robots.selected_page_error_allows)?
            .warning)
    }

    /// Cached robots document for an origin, with the bounded 429/network-error
    /// throttling and failure caching shared by every robots consumer.
    async fn robots_for(
        &self,
        context: &Context,
        target: &PublicUrl,
    ) -> Result<Arc<RobotsDocument>> {
        let key = self.key(context, &format!("robots:{}", target.origin()))?;
        self.robots
            .get_or_init_cancellable(key, &context.stop, || async {
                let result = self.robots_document(context, target).await;
                let (document, weight, ttl) = match result {
                    Ok(value) => value,
                    Err(ErrorCode::EgressUnavailable | ErrorCode::Timeout) => (
                        RobotsDocument::Unavailable,
                        64,
                        self.config.robots.cache_seconds.min(10),
                    ),
                    Err(error) => return Err(error),
                };
                let ttl = if matches!(document, RobotsDocument::Unavailable) {
                    ttl.min(10)
                } else {
                    ttl
                };
                Ok((document, Duration::from_secs(ttl), weight))
            })
            .await
            .map(|(document, _)| document)
    }

    /// Minimum spacing requested by the matched robots groups for automatic
    /// crawl requests. Errors and non-rules documents yield zero; access policy
    /// is still enforced by `discovery_decision`.
    pub async fn crawl_interval(&self, context: &Context, target: &PublicUrl) -> Result<Duration> {
        let document = self.robots_for(context, target).await?;
        Ok(match document.as_ref() {
            RobotsDocument::Rules(rules) => rules.crawl_interval(),
            _ => Duration::ZERO,
        })
    }

    /// Discovery robots decision for bounded crawling. Unlike an explicitly
    /// selected page, an unavailable or throttled robots document never falls
    /// back to reading: it pauses further discovery for the origin. A valid
    /// disallow or access block skips only that discovered page. Cancellation
    /// still propagates so the caller can stop promptly.
    pub async fn discovery_decision(
        &self,
        context: &Context,
        target: &PublicUrl,
    ) -> Result<DiscoveryDecision> {
        match self
            .allowed_kind(context, target, AccessKind::Discovery)
            .await
        {
            Ok(_) => Ok(DiscoveryDecision::Allowed),
            Err(ErrorCode::Cancelled) => Err(ErrorCode::Cancelled),
            Err(ErrorCode::PolicyDenied | ErrorCode::AccessBlocked) => Ok(DiscoveryDecision::Skip),
            // Network/5xx (unavailable), 429 throttling and any malformed robots
            // response all fail closed for automatic discovery.
            Err(_) => Ok(DiscoveryDecision::Pause),
        }
    }

    /// Selected-page robots decision for callers outside the local fetch path
    /// (explicit provider scraping). A disallowed path fails before any network
    /// call; the returned flag reports an unavailable robots document. This is
    /// the exact check `fetch` runs, so a provider cannot bypass an access block.
    pub async fn selected_page_policy(
        &self,
        context: &Context,
        target: &PublicUrl,
    ) -> Result<bool> {
        self.allowed(context, target).await
    }

    async fn robots_document(
        &self,
        context: &Context,
        target: &PublicUrl,
    ) -> Result<(RobotsDocument, usize, u64)> {
        let mut target = PublicUrl::parse(&format!("{}/robots.txt", target.origin()))?;
        let mut seen = HashSet::new();
        for redirect in 0..=self.config.limits.redirects {
            if !seen.insert(target.request_url().to_string()) {
                return Err(ErrorCode::InvalidResponse);
            }
            let response = self
                .read_attempts(context, &target, self.config.robots.max_bytes as u64)
                .await?;
            if [301, 302, 303, 307, 308].contains(&response.status) {
                if redirect == self.config.limits.redirects {
                    return Err(ErrorCode::SizeLimit);
                }
                target = target.redirect(
                    response
                        .headers
                        .get("location")
                        .ok_or(ErrorCode::InvalidResponse)?
                        .to_str()
                        .map_err(|_| ErrorCode::InvalidResponse)?,
                )?;
            } else {
                let document = RobotsDocument::from_response(
                    response.status,
                    &response.body,
                    &self.config.robots.user_agent,
                    self.config.robots.max_bytes,
                )?;
                let ttl = if response.status == 429 {
                    // Only a body-free Throttled marker is retained. Even a
                    // no-store response can request a bounded cooldown; using
                    // HTTP freshness here would immediately retry the endpoint.
                    let retry = if response.headers.contains_key("retry-after") {
                        retry_after_headers(&response.headers, Duration::MAX)
                            .map(|delay| delay.as_secs().min(60))
                            .unwrap_or(60)
                    } else {
                        10
                    };
                    retry.max(1)
                } else {
                    cache_ttl(&response.headers, self.config.robots.cache_seconds).as_secs()
                };
                return Ok((document, response.body.len().saturating_mul(6).max(64), ttl));
            }
        }
        Err(ErrorCode::InvalidResponse)
    }

    async fn read_attempts(
        &self,
        context: &Context,
        target: &PublicUrl,
        maximum: u64,
    ) -> Result<HttpResponse> {
        for attempt in 0..=self.config.limits.retries {
            let request = HttpRequest {
                target: target.clone(),
                headers: [(
                    "accept".parse().map_err(|_| ErrorCode::InvalidRequest)?,
                    HeaderValue::from_static(
                        "text/html,application/pdf,text/plain,application/json;q=0.8,*/*;q=0.1",
                    ),
                )]
                .into_iter()
                .collect(),
                max_bytes: maximum,
                micro_usd: 0,
                errors_are_unbilled: false,
                query: false,
            };
            let response = self
                .http
                .get(context.owner, context.job, request, &context.stop)
                .await;
            if attempt == self.config.limits.retries {
                return response;
            }
            let remaining = context.deadline.saturating_duration_since(Instant::now());
            let Some(delay) = retry_delay(&response, attempt, remaining) else {
                return response;
            };
            tokio::select! { biased; _ = context.stop.cancelled() => return Err(ErrorCode::Cancelled), _ = tokio::time::sleep(delay) => () }
        }
        Err(ErrorCode::InvalidResponse)
    }
}

fn retry_delay(
    response: &Result<HttpResponse>,
    attempt: usize,
    remaining: Duration,
) -> Option<Duration> {
    let eligible = match response {
        Ok(response) => matches!(response.status, 429 | 502 | 503 | 504),
        Err(error) => matches!(
            error,
            ErrorCode::Timeout | ErrorCode::EgressUnavailable | ErrorCode::InvalidResponse
        ),
    };
    if !eligible {
        return None;
    }
    let delay = if let Ok(response) = response
        && response.headers.contains_key("retry-after")
    {
        retry_after_headers(&response.headers, remaining)?
    } else {
        Duration::from_secs(1_u64.checked_shl(u32::try_from(attempt).ok()?)?)
    };
    (delay < remaining).then_some(delay)
}

fn browser_status(
    response: &HttpResponse,
    target: &PublicUrl,
    redirects: u32,
    config: &Config,
) -> Result<()> {
    if response
        .headers
        .get("cf-mitigated")
        .is_some_and(|value| value == "challenge")
    {
        return Err(ErrorCode::AccessBlocked);
    }
    match response.status {
        200..=299 | 304 => (),
        301 | 302 | 303 | 307 | 308 => {
            if redirects as usize == config.limits.redirects {
                return Err(ErrorCode::SizeLimit);
            }
            target.redirect(
                response
                    .headers
                    .get("location")
                    .ok_or(ErrorCode::InvalidResponse)?
                    .to_str()
                    .map_err(|_| ErrorCode::InvalidResponse)?,
            )?;
        }
        401 | 403 | 407 | 451 => return Err(ErrorCode::AccessBlocked),
        404 | 410 => return Err(ErrorCode::NotFound),
        429 => return Err(ErrorCode::RateLimited),
        _ => return Err(ErrorCode::InvalidResponse),
    }
    let html = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "text/html" | "application/xhtml+xml"
            )
        });
    if response.body.len() as u64 > config.limits.pdf_bytes
        || (html && response.body.len() as u64 > config.limits.html_bytes)
    {
        return Err(ErrorCode::SizeLimit);
    }
    Ok(())
}

fn extraction_warnings(
    parsed: &[crate::worker::ExtractionWarning],
    warnings: &mut Vec<SourceWarning>,
    rendered: bool,
) {
    use crate::worker::ExtractionWarning;
    for warning in parsed {
        // Scripts can remain in a rendered DOM whose short text was actually
        // observed. The HTTP-only JS heuristic cannot invalidate that evidence.
        if rendered && *warning == ExtractionWarning::JavascriptRequired {
            continue;
        }
        let mapped = match warning {
            ExtractionWarning::ReadabilityUnavailable => SourceWarning::ReadabilityUnavailable,
            ExtractionWarning::StreamingHtmlRecovered => SourceWarning::StreamingHtmlRecovered,
            ExtractionWarning::PageShell => SourceWarning::PageShell,
            ExtractionWarning::JavascriptRequired => SourceWarning::JavascriptRequired,
            _ => SourceWarning::PartialExtraction,
        };
        if !warnings
            .iter()
            .any(|existing| std::mem::discriminant(existing) == std::mem::discriminant(&mapped))
        {
            warnings.push(mapped);
        }
    }
}

fn raw(bytes: &[u8]) -> Evidence {
    Evidence {
        kind: RepresentationKind::HttpEntity,
        bytes: bytes.to_vec(),
        extraction_version: "http/entity-decoded/1".into(),
        derived_from: None,
        pdf_page: None,
        text: false,
    }
}

pub fn cache_ttl(headers: &HeaderMap, maximum: u64) -> Duration {
    if headers.contains_key("set-cookie") {
        return Duration::ZERO;
    }
    // Document requests use one fixed Accept value and one client per Fetcher.
    // Accept-Encoding, Accept-Language (absent) and User-Agent are therefore
    // stable for this cache; other request-dependent responses cannot be reused.
    for vary in headers.get_all("vary").iter() {
        if vary.to_str().ok().is_none_or(|v| {
            v.split(',').any(|name| {
                !matches!(
                    name.trim().to_ascii_lowercase().as_str(),
                    "accept" | "accept-encoding" | "accept-language" | "user-agent"
                )
            })
        }) {
            return Duration::ZERO;
        }
    }
    let mut seconds = maximum;
    let mut max_age_present = false;
    for control in headers.get_all("cache-control").iter() {
        let Ok(control) = control.to_str() else {
            return Duration::ZERO;
        };
        for directive in control.split(',') {
            let directive = directive.trim().to_ascii_lowercase();
            // A noncanonical space around '=' must not hide a restrictive
            // directive or turn a zero age into the configured maximum.
            let (name, value) = match directive.split_once('=') {
                Some((name, value)) => (name.trim(), Some(value.trim())),
                None => (directive.as_str(), None),
            };
            if matches!(name, "no-cache" | "no-store" | "private") {
                return Duration::ZERO;
            }
            if matches!(name, "max-age" | "s-maxage") {
                let Some(value) = value else {
                    return Duration::ZERO;
                };
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value);
                let Ok(value) = value.parse::<u64>() else {
                    return Duration::ZERO;
                };
                max_age_present = true;
                seconds = seconds.min(value);
            }
        }
    }
    let mut oldest_age = 0;
    for age in headers.get_all("age").iter() {
        let Some(age) = age.to_str().ok().and_then(|v| v.parse::<u64>().ok()) else {
            return Duration::ZERO;
        };
        oldest_age = oldest_age.max(age);
    }
    seconds = seconds.saturating_sub(oldest_age);
    // Only an explicit age directive supersedes Expires. Unknown or conflicting
    // date fields cannot justify keeping a response in a shared job cache.
    if !max_age_present {
        let mut expires = headers.get_all("expires").iter();
        if let Some(value) = expires.next() {
            if expires.next().is_some() {
                return Duration::ZERO;
            }
            let Some(expiry) = value
                .to_str()
                .ok()
                .and_then(|v| chrono::DateTime::parse_from_rfc2822(v.trim()).ok())
            else {
                return Duration::ZERO;
            };
            let mut bound = (expiry.timestamp() - chrono::Utc::now().timestamp()).max(0) as u64;
            let mut dates = headers.get_all("date").iter();
            if let Some(value) = dates.next() {
                if dates.next().is_some() {
                    return Duration::ZERO;
                }
                let Some(date) = value
                    .to_str()
                    .ok()
                    .and_then(|v| chrono::DateTime::parse_from_rfc2822(v.trim()).ok())
                else {
                    return Duration::ZERO;
                };
                bound = bound.min((expiry.timestamp() - date.timestamp()).max(0) as u64);
            }
            seconds = seconds.min(bound.saturating_sub(oldest_age));
        }
    }
    Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::RequestedLimits;
    use std::collections::HashMap;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio_util::sync::CancellationToken;

    struct Route {
        status: u16,
        body: &'static [u8],
        headers: HeaderMap,
    }
    struct Fixture {
        routes: HashMap<&'static str, Route>,
        calls: Mutex<Vec<String>>,
        barrier: Option<tokio::sync::Barrier>,
    }
    #[async_trait::async_trait]
    impl Transport for Fixture {
        async fn get(
            &self,
            _: u32,
            _: uuid::Uuid,
            request: HttpRequest,
            _: &CancellationToken,
        ) -> Result<HttpResponse> {
            let path = request.target.url().path();
            self.calls.lock().unwrap().push(path.to_owned());
            assert!(!request.headers.contains_key("authorization"));
            assert!(!request.headers.contains_key("x-subscription-token"));
            let route = self.routes.get(path).ok_or(ErrorCode::EgressUnavailable)?;
            if path != "/robots.txt"
                && let Some(barrier) = &self.barrier
            {
                tokio::time::timeout(Duration::from_secs(2), barrier.wait())
                    .await
                    .unwrap();
            }
            Ok(HttpResponse {
                status: route.status,
                body: route.body.to_vec(),
                headers: route.headers.clone(),
            })
        }
    }
    struct FixtureParser {
        ledger: Arc<Ledger>,
        extractions: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl Parser for FixtureParser {
        async fn inspect(&self, _: &Context, _: ExtractionInput<'_>) -> Result<PdfInfo> {
            Ok(PdfInfo {
                pages: 2,
                title: "PDF fixture".into(),
            })
        }
        async fn extract(
            &self,
            context: &Context,
            input: ExtractionInput<'_>,
        ) -> Result<ParsedDocument> {
            self.extractions.fetch_add(1, Ordering::SeqCst);
            if matches!(input.kind, DocumentKind::Pdf) {
                assert_eq!(
                    self.ledger
                        .get(context.owner, context.job)
                        .unwrap()
                        .usage
                        .pdf_pages,
                    2,
                    "PDF work ran before reservation"
                );
                Ok(ParsedDocument {
                    version: 1,
                    title: "PDF fixture".into(),
                    pages: vec!["first".into(), "second".into()],
                    readable_text: None,
                    extraction_version: "fixture/pdf/1".into(),
                    links: vec![],
                    warnings: vec![],
                })
            } else {
                worker::parse_text(input.bytes, "text/plain; charset=utf-8")
            }
        }
    }
    fn route(status: u16, body: &'static [u8], media: &'static str) -> Route {
        Route {
            status,
            body,
            headers: [(
                "content-type".parse().unwrap(),
                HeaderValue::from_static(media),
            )]
            .into_iter()
            .collect(),
        }
    }
    fn setup(
        root: &tempfile::TempDir,
        routes: HashMap<&'static str, Route>,
        barrier: bool,
        privacy: Privacy,
    ) -> (
        Fetcher,
        Arc<Fixture>,
        Arc<FixtureParser>,
        Arc<EvidenceStore>,
        Context,
    ) {
        let config = Config {
            state_directory: root.path().join("state"),
            privacy,
            limits: crate::config::Limits {
                retries: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        std::fs::create_dir_all(&config.state_directory).unwrap();
        let ledger = Ledger::open(
            &config.state_directory.join("ledger.sqlite"),
            config.limits.clone(),
        )
        .unwrap();
        let job = ledger
            .start(
                1001,
                RequestedLimits {
                    pdf_pages: Some(2),
                    ..Default::default()
                },
            )
            .unwrap();
        let context = Context {
            owner: 1001,
            job: job.id,
            deadline: Instant::now() + Duration::from_secs(5),
            stop: CancellationToken::new(),
        };
        let transport = Arc::new(Fixture {
            routes,
            calls: Mutex::new(vec![]),
            barrier: barrier.then(|| tokio::sync::Barrier::new(2)),
        });
        let parser = Arc::new(FixtureParser {
            ledger: ledger.clone(),
            extractions: AtomicUsize::new(0),
        });
        let store = EvidenceStore::open(&config, root.path().to_owned()).unwrap();
        let fetcher = Fetcher::new(
            config,
            transport.clone(),
            Some(parser.clone()),
            ledger,
            store.clone(),
        )
        .unwrap();
        (fetcher, transport, parser, store, context)
    }
    fn target(path: &str) -> PublicUrl {
        PublicUrl::parse(&format!("https://example.com{path}")).unwrap()
    }

    fn browser_input(path: &str) -> crate::browser::wire::HttpRequest {
        crate::browser::wire::HttpRequest {
            url: target(path).as_str().into(),
            method: "GET".into(),
            headers: vec![],
            body_base64: String::new(),
            resource_type: "Document".into(),
            main_document: true,
            redirects: 0,
        }
    }

    fn snapshot() -> crate::browser::read::PageSnapshot {
        let html = "<html><body>Rendered é 👩‍🔬 quote.</body></html>"
            .as_bytes()
            .to_vec();
        crate::browser::read::PageSnapshot {
            metadata: crate::browser::wire::Snapshot {
                version: uuid::Uuid::new_v4(),
                url: target("/page").as_str().into(),
                title: "Fixture".into(),
                html_bytes: html.len() as u64,
                html_sha256: sha256(&html),
                references: vec![],
                truncated_references: false,
                pending_requests: false,
                request_errors: vec![],
            },
            html,
        }
    }

    #[tokio::test]
    async fn browser_broker_rechecks_targets_robots_and_retains_denied_response() {
        use crate::browser::{broker::JobBroker, session::Broker};
        let root = tempfile::tempdir().unwrap();
        let mut redirect = route(302, b"redirect evidence", "text/plain");
        redirect.headers.insert(
            "location",
            HeaderValue::from_static("http://127.0.0.1/private"),
        );
        let (fetcher, transport, _, store, context) = setup(
            &root,
            [
                (
                    "/robots.txt",
                    route(200, b"User-agent: *\nDisallow: /private", "text/plain"),
                ),
                ("/redirect", redirect),
                (
                    "/denied",
                    route(403, b"Access denied fixture.", "text/plain"),
                ),
            ]
            .into(),
            false,
            Privacy::Practical,
        );
        let broker = JobBroker::new(Arc::new(fetcher), context, 8).unwrap();
        let mut private = browser_input("/page");
        private.url = "http://127.0.0.1/private".into();
        for (input, expected) in [
            (private, ErrorCode::DestinationDenied),
            (browser_input("/private"), ErrorCode::PolicyDenied),
            (browser_input("/redirect"), ErrorCode::DestinationDenied),
        ] {
            assert_eq!(
                broker.request(input, CancellationToken::new()).await.err(),
                Some(expected)
            );
        }
        assert!(matches!(
            broker
                .request(browser_input("/denied"), CancellationToken::new())
                .await,
            Err(ErrorCode::AccessBlocked)
        ));
        broker.drain().await;
        let receipts = broker.receipts().unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            *transport.calls.lock().unwrap(),
            ["/robots.txt", "/redirect", "/denied"]
        );
        for receipt in receipts {
            let source = store.get(1001, receipt.source.id).await.unwrap();
            assert_eq!(
                source.representations[0].kind,
                RepresentationKind::HttpEntity
            );
            assert!(receipt.error.is_some());
        }
    }

    #[tokio::test]
    async fn browser_document_budget_is_reserved_before_http_and_retries_are_bounded() {
        let root = tempfile::tempdir().unwrap();
        let mut limited = route(429, b"Rate limit fixture.", "text/plain");
        limited
            .headers
            .insert("retry-after", HeaderValue::from_static("0"));
        let (mut fetcher, transport, _, _, mut context) = setup(
            &root,
            [
                ("/robots.txt", route(404, b"", "text/plain")),
                ("/page", limited),
            ]
            .into(),
            false,
            Privacy::Practical,
        );
        fetcher.config.limits.retries = 2;
        let job = fetcher
            .ledger
            .start(
                context.owner,
                RequestedLimits {
                    documents: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();
        context.job = job.id;
        let result = fetcher
            .browser_entity(&context, browser_input("/page"))
            .await
            .unwrap();
        assert_eq!(result.error, Some(ErrorCode::RateLimited));
        assert_eq!(
            transport
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|url| *url == "/page")
                .count(),
            3
        );
        assert_eq!(
            fetcher
                .ledger
                .get(context.owner, context.job)
                .unwrap()
                .usage
                .documents,
            1
        );
        assert!(matches!(
            fetcher
                .browser_entity(&context, browser_input("/page"))
                .await,
            Err(ErrorCode::BudgetExceeded)
        ));
        assert_eq!(transport.calls.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn browser_raw_dom_and_extracted_text_have_distinct_provenance_and_strict_lifetime() {
        let root = tempfile::tempdir().unwrap();
        let (fetcher, _, _, store, context) = setup(
            &root,
            [
                ("/robots.txt", route(404, b"", "text/plain")),
                (
                    "/page",
                    route(200, b"<html>Original HTTP.</html>", "text/html"),
                ),
            ]
            .into(),
            false,
            Privacy::Strict,
        );
        let original = fetcher
            .browser_entity(&context, browser_input("/page"))
            .await
            .unwrap();
        let snapshot = snapshot();
        let rendered = fetcher
            .rendered(&context, &target("/page"), &snapshot)
            .await
            .unwrap();
        assert!(rendered.error.is_none());
        assert_ne!(original.source.id, rendered.dom_source_id);
        assert_ne!(rendered.source.id, rendered.dom_source_id);
        let dom = &rendered.source.representations[0];
        let text = &rendered.source.representations[1];
        assert_eq!(dom.kind, RepresentationKind::RenderedDom);
        assert_eq!(text.kind, RepresentationKind::Text);
        assert_ne!(dom.id, text.id);
        assert_eq!(text.derived_from, Some(dom.id));
        assert_ne!(dom.sha256, original.source.representations[0].sha256);
        let chunk = store
            .read(
                context.owner,
                rendered.dom_source_id,
                store
                    .get(context.owner, rendered.dom_source_id)
                    .await
                    .unwrap()
                    .representations[0]
                    .id,
                None,
                4096,
            )
            .await
            .unwrap();
        assert_eq!(chunk.content.as_bytes(), snapshot.html);
        let used = fetcher
            .ledger
            .get(context.owner, context.job)
            .unwrap()
            .usage
            .used_bytes;
        assert_eq!(used, snapshot.html.len() as u64);
        store.finish_job(context.owner, context.job).unwrap();
        for id in [
            original.source.id,
            rendered.dom_source_id,
            rendered.source.id,
        ] {
            assert!(matches!(
                store.get(context.owner, id).await,
                Err(ErrorCode::SourceExpired)
            ));
        }
    }

    #[tokio::test]
    async fn rendered_dom_survives_unavailable_parser_and_bad_hash_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (mut fetcher, _, _, store, context) =
            setup(&root, HashMap::new(), false, Privacy::Practical);
        fetcher.parser = None;
        let mut snapshot = snapshot();
        let result = fetcher
            .rendered(&context, &target("/page"), &snapshot)
            .await
            .unwrap();
        assert_eq!(result.error, Some(ErrorCode::ProviderUnavailable));
        assert_eq!(result.source.id, result.dom_source_id);
        assert_eq!(
            result.source.representations[0].kind,
            RepresentationKind::RenderedDom
        );
        store
            .get(context.owner, result.dom_source_id)
            .await
            .unwrap();
        snapshot.html.push(b'x');
        assert!(matches!(
            fetcher
                .rendered(&context, &target("/page"), &snapshot)
                .await,
            Err(ErrorCode::InvalidResponse)
        ));
    }

    #[tokio::test]
    async fn concurrent_pages_share_robots_and_reuse_exact_evidence() {
        let root = tempfile::tempdir().unwrap();
        let routes = [
            (
                "/robots.txt",
                route(200, b"User-agent: *\nDisallow: /private", "text/plain"),
            ),
            ("/one", route(200, b"one", "text/plain")),
            ("/two", route(200, b"two", "text/plain")),
        ]
        .into();
        let (fetcher, transport, _, _, context) = setup(&root, routes, true, Privacy::Practical);
        let (one, two) = (target("/one"), target("/two"));
        let (a, b) = tokio::join!(fetcher.fetch(&context, &one), fetcher.fetch(&context, &two));
        let a = a.unwrap();
        let b = b.unwrap();
        assert!(a.error.is_none() && b.error.is_none());
        let cached = fetcher.fetch(&context, &one).await.unwrap();
        assert!(cached.cache_hit);
        assert_eq!(cached.source.id, a.source.id);
        assert_eq!(
            transport
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|path| *path == "/robots.txt")
                .count(),
            1
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn redirect_rechecks_robots_and_never_requests_disallowed_path() {
        let root = tempfile::tempdir().unwrap();
        let mut redirect = route(302, b"", "text/plain");
        redirect
            .headers
            .insert("location", HeaderValue::from_static("/private"));
        let routes = [
            (
                "/robots.txt",
                route(200, b"User-agent: *\nDisallow: /private", "text/plain"),
            ),
            ("/start", redirect),
        ]
        .into();
        let (fetcher, transport, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        assert!(matches!(
            fetcher.fetch(&context, &target("/start")).await,
            Err(ErrorCode::PolicyDenied)
        ));
        assert_eq!(*transport.calls.lock().unwrap(), ["/robots.txt", "/start"]);
    }

    #[tokio::test]
    async fn parallel_pdf_budget_is_reserved_before_extraction_and_raw_survives() {
        let root = tempfile::tempdir().unwrap();
        let routes = [
            ("/robots.txt", route(404, b"", "text/plain")),
            ("/a.pdf", route(200, b"%PDF-first", "application/pdf")),
            ("/b.pdf", route(200, b"%PDF-second", "application/pdf")),
        ]
        .into();
        let (fetcher, _, parser, store, context) = setup(&root, routes, true, Privacy::Practical);
        let (a, b) = (target("/a.pdf"), target("/b.pdf"));
        let (a, b) = tokio::join!(fetcher.fetch(&context, &a), fetcher.fetch(&context, &b));
        let records = [a.unwrap(), b.unwrap()];
        assert_eq!(records.iter().filter(|r| r.error.is_none()).count(), 1);
        assert_eq!(
            records
                .iter()
                .filter(|r| r.error == Some(ErrorCode::BudgetExceeded))
                .count(),
            1
        );
        assert_eq!(parser.extractions.load(Ordering::SeqCst), 1);
        for record in records {
            assert!(store.get(1001, record.raw_source_id).await.is_ok());
        }
    }

    #[tokio::test]
    async fn expired_ephemeral_evidence_invalidates_cached_source_ids() {
        let root = tempfile::tempdir().unwrap();
        let routes = [
            ("/robots.txt", route(404, b"", "text/plain")),
            ("/one", route(200, b"ephemeral canary", "text/plain")),
        ]
        .into();
        let (fetcher, transport, _, store, context) = setup(&root, routes, false, Privacy::Strict);
        let first = fetcher.fetch(&context, &target("/one")).await.unwrap();
        store.finish_job(1001, context.job).unwrap();
        assert!(matches!(
            store.get(1001, first.source.id).await,
            Err(ErrorCode::SourceExpired)
        ));
        let second = fetcher.fetch(&context, &target("/one")).await.unwrap();
        assert_ne!(first.source.id, second.source.id);
        assert!(!second.cache_hit);
        assert_eq!(
            transport
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == "/one")
                .count(),
            2
        );
        assert!(!root.path().join("state/evidence").exists());
        assert!(root.path().join("state/ledger.sqlite").exists());
    }

    #[tokio::test]
    async fn access_block_keeps_raw_but_never_invokes_parser_or_browser_hint() {
        let root = tempfile::tempdir().unwrap();
        let routes = [
            ("/robots.txt", route(404, b"", "text/plain")),
            (
                "/blocked",
                route(403, b"<script>challenge()</script>", "text/html"),
            ),
        ]
        .into();
        let (fetcher, _, parser, store, context) = setup(&root, routes, false, Privacy::Practical);
        let record = fetcher.fetch(&context, &target("/blocked")).await.unwrap();
        assert_eq!(record.error, Some(ErrorCode::AccessBlocked));
        assert!(!record.javascript_hint);
        assert_eq!(parser.extractions.load(Ordering::SeqCst), 0);
        assert!(store.get(1001, record.raw_source_id).await.is_ok());
    }

    #[tokio::test]
    async fn discovery_robots_skips_disallowed_pages_and_pauses_on_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let routes = [(
            "/robots.txt",
            route(200, b"User-agent: *\nDisallow: /private", "text/plain"),
        )]
        .into();
        let (fetcher, _, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        assert_eq!(
            fetcher
                .discovery_decision(&context, &target("/public"))
                .await
                .unwrap(),
            DiscoveryDecision::Allowed
        );
        assert_eq!(
            fetcher
                .discovery_decision(&context, &target("/private"))
                .await
                .unwrap(),
            DiscoveryDecision::Skip
        );
        // A selected page keeps the same valid disallow as binding.
        assert_eq!(
            fetcher
                .selected_page_policy(&context, &target("/private"))
                .await,
            Err(ErrorCode::PolicyDenied)
        );

        // A 5xx robots response pauses discovery but still allows a selected page.
        let root = tempfile::tempdir().unwrap();
        let routes = [("/robots.txt", route(503, b"", "text/plain"))].into();
        let (fetcher, _, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        assert_eq!(
            fetcher
                .discovery_decision(&context, &target("/public"))
                .await
                .unwrap(),
            DiscoveryDecision::Pause
        );
        assert_eq!(
            fetcher
                .selected_page_policy(&context, &target("/public"))
                .await,
            Ok(true)
        );
    }

    #[tokio::test]
    async fn robots_429_retry_after_is_honored_even_with_no_store() {
        let root = tempfile::tempdir().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("retry-after", HeaderValue::from_static("3"));
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        let routes = [(
            "/robots.txt",
            Route {
                status: 429,
                body: b"",
                headers,
            },
        )]
        .into();
        let (fetcher, transport, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        // The throttled robots document fails a selected-page fetch closed.
        assert_eq!(
            fetcher
                .selected_page_policy(&context, &target("/public"))
                .await,
            Err(ErrorCode::RateLimited)
        );
        // Within Retry-After, only the body-free cooldown marker is reused;
        // no-store must not cause another immediate robots request.
        assert_eq!(
            fetcher
                .selected_page_policy(&context, &target("/public"))
                .await,
            Err(ErrorCode::RateLimited)
        );
        assert_eq!(
            *transport.calls.lock().unwrap(),
            ["/robots.txt".to_string()]
        );
        // Automatic discovery pauses on the same throttled origin.
        assert_eq!(
            fetcher
                .discovery_decision(&context, &target("/public"))
                .await
                .unwrap(),
            DiscoveryDecision::Pause
        );
    }

    #[tokio::test]
    async fn robots_duplicate_retry_after_uses_bounded_longest_cooldown() {
        let root = tempfile::tempdir().unwrap();
        let mut headers = HeaderMap::new();
        headers.append("retry-after", HeaderValue::from_static("0"));
        headers.append("retry-after", HeaderValue::from_static("120"));
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        let routes = [(
            "/robots.txt",
            Route {
                status: 429,
                body: b"",
                headers,
            },
        )]
        .into();
        let (fetcher, _, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        let (document, _, seconds) = fetcher
            .robots_document(&context, &target("/public"))
            .await
            .unwrap();
        assert!(matches!(document, RobotsDocument::Throttled));
        assert_eq!(seconds, 60);
    }

    #[test]
    fn target_retry_does_not_ignore_a_later_long_retry_after() {
        let mut headers = HeaderMap::new();
        headers.append("retry-after", HeaderValue::from_static("0"));
        headers.append("retry-after", HeaderValue::from_static("120"));
        let response = Ok(HttpResponse {
            status: 429,
            headers,
            body: vec![],
        });
        assert_eq!(retry_delay(&response, 0, Duration::from_secs(30)), None);
    }

    #[tokio::test]
    async fn crawl_interval_reports_the_matched_groups_request() {
        let root = tempfile::tempdir().unwrap();
        let routes = [(
            "/robots.txt",
            route(
                200,
                b"User-agent: *\nCrawl-delay: 5\nDisallow: /x\n",
                "text/plain",
            ),
        )]
        .into();
        let (fetcher, _, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        assert_eq!(
            fetcher
                .crawl_interval(&context, &target("/public"))
                .await
                .unwrap(),
            Duration::from_secs(5)
        );
        // Without a pacing directive there is no forced pause.
        let root = tempfile::tempdir().unwrap();
        let routes = [("/robots.txt", route(404, b"", "text/plain"))].into();
        let (fetcher, _, _, _, context) = setup(&root, routes, false, Privacy::Practical);
        assert_eq!(
            fetcher
                .crawl_interval(&context, &target("/public"))
                .await
                .unwrap(),
            Duration::ZERO
        );
    }

    #[test]
    fn cache_control_variation_and_age_bound_reuse() {
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", HeaderValue::from_static("max-age=30"));
        headers.insert("age", HeaderValue::from_static("20"));
        assert_eq!(cache_ttl(&headers, 900), Duration::from_secs(10));
        for value in ["no-store", "no-cache", "private=\"field\""] {
            headers.insert("cache-control", HeaderValue::from_static(value));
            assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);
        }
        headers.clear();
        headers.insert("vary", HeaderValue::from_static("Cookie"));
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);
    }

    #[test]
    fn later_cache_control_or_vary_fields_still_forbid_reuse() {
        let mut headers = HeaderMap::new();
        headers.append("cache-control", HeaderValue::from_static("public"));
        headers.append("cache-control", HeaderValue::from_static("no-store"));
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);

        headers.clear();
        headers.append("vary", HeaderValue::from_static("Accept"));
        headers.append("vary", HeaderValue::from_static("Cookie"));
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);

        headers.clear();
        headers.append("age", HeaderValue::from_static("1"));
        headers.append("age", HeaderValue::from_static("900"));
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);
    }

    #[test]
    fn whitespace_around_cache_directive_equals_cannot_extend_reuse() {
        let mut headers = HeaderMap::new();
        for directive in [
            "max-age = 0",
            "s-maxage = 0",
            "private = \"Authorization\"",
            "no-cache = \"Authorization\"",
            "no-store = invalid",
            "max-age",
            "max-age = \"0",
        ] {
            headers.insert("cache-control", HeaderValue::from_str(directive).unwrap());
            assert_eq!(cache_ttl(&headers, 900), Duration::ZERO, "{directive}");
        }
        headers.insert(
            "cache-control",
            HeaderValue::from_static("max-age = \"10\""),
        );
        assert_eq!(cache_ttl(&headers, 900), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn repeated_no_store_prevents_cross_job_source_reuse() {
        let root = tempfile::tempdir().unwrap();
        let mut page = route(200, b"not reusable", "text/plain");
        page.headers
            .append("cache-control", HeaderValue::from_static("public"));
        page.headers
            .append("cache-control", HeaderValue::from_static("no-store"));
        let routes = [
            ("/robots.txt", route(404, b"", "text/plain")),
            ("/page", page),
        ]
        .into();
        let (fetcher, transport, _, _, first_job) = setup(&root, routes, false, Privacy::Practical);
        let first = fetcher.fetch(&first_job, &target("/page")).await.unwrap();
        assert!(!first.cache_hit);

        let second_job = fetcher
            .ledger
            .start(1001, RequestedLimits::default())
            .unwrap();
        let context = Context {
            owner: 1001,
            job: second_job.id,
            deadline: Instant::now() + Duration::from_secs(5),
            stop: CancellationToken::new(),
        };
        let second = fetcher.fetch(&context, &target("/page")).await.unwrap();
        assert!(!second.cache_hit);
        assert_eq!(
            transport
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|path| *path == "/page")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn vary_reuses_only_stable_request_headers_across_jobs() {
        for (vary, reusable) in [
            ("Accept, Accept-Encoding, Accept-Language, User-Agent", true),
            ("Accept, X-Experiment", false),
            ("*", false),
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut page = route(200, b"varying page", "text/plain");
            page.headers
                .insert("vary", HeaderValue::from_str(vary).unwrap());
            let routes = [
                ("/robots.txt", route(404, b"", "text/plain")),
                ("/page", page),
            ]
            .into();
            let (fetcher, transport, _, _, first_job) =
                setup(&root, routes, false, Privacy::Practical);
            let first = fetcher.fetch(&first_job, &target("/page")).await.unwrap();
            let second_job = fetcher
                .ledger
                .start(1001, RequestedLimits::default())
                .unwrap();
            let context = Context {
                owner: 1001,
                job: second_job.id,
                deadline: Instant::now() + Duration::from_secs(5),
                stop: CancellationToken::new(),
            };
            let second = fetcher.fetch(&context, &target("/page")).await.unwrap();
            assert_eq!(second.cache_hit, reusable, "{vary}");
            assert_eq!(first.source.id == second.source.id, reusable, "{vary}");
            assert_eq!(
                transport
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|path| *path == "/page")
                    .count(),
                if reusable { 1 } else { 2 },
                "{vary}"
            );
        }
    }

    #[test]
    fn expires_header_bounds_reuse_unless_cache_control_is_fresher() {
        // A future Expires bounds reuse to its remaining time.
        let future = chrono::Utc::now() + chrono::Duration::seconds(120);
        let mut headers = HeaderMap::new();
        headers.insert(
            "expires",
            HeaderValue::from_str(&future.to_rfc2822()).unwrap(),
        );
        let ttl = cache_ttl(&headers, 900).as_secs();
        assert!((110..=120).contains(&ttl), "{ttl}");
        // A past Expires forbids reuse.
        let past = chrono::Utc::now() - chrono::Duration::seconds(60);
        headers.insert(
            "expires",
            HeaderValue::from_str(&past.to_rfc2822()).unwrap(),
        );
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);
        // Cache-Control wins over an Expires value.
        headers.insert("cache-control", HeaderValue::from_static("max-age=30"));
        headers.insert(
            "expires",
            HeaderValue::from_str(&future.to_rfc2822()).unwrap(),
        );
        assert_eq!(cache_ttl(&headers, 900), Duration::from_secs(30));
    }

    #[test]
    fn public_directive_does_not_override_expired_or_uncertain_expires() {
        let now = chrono::Utc::now();
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", HeaderValue::from_static("public"));
        headers.insert(
            "expires",
            HeaderValue::from_str(&(now - chrono::Duration::seconds(60)).to_rfc2822()).unwrap(),
        );
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);

        headers.insert("expires", HeaderValue::from_static("not-a-date"));
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);

        let server_date = now + chrono::Duration::hours(1);
        headers.insert(
            "date",
            HeaderValue::from_str(&server_date.to_rfc2822()).unwrap(),
        );
        headers.insert(
            "expires",
            HeaderValue::from_str(&(server_date + chrono::Duration::seconds(10)).to_rfc2822())
                .unwrap(),
        );
        assert!(cache_ttl(&headers, 900) <= Duration::from_secs(10));

        headers.clear();
        headers.insert("cache-control", HeaderValue::from_static("s-maxage=0"));
        headers.insert(
            "expires",
            HeaderValue::from_str(&(now + chrono::Duration::hours(1)).to_rfc2822()).unwrap(),
        );
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);

        headers.remove("cache-control");
        headers.append(
            "expires",
            HeaderValue::from_str(&(now + chrono::Duration::hours(2)).to_rfc2822()).unwrap(),
        );
        assert_eq!(cache_ttl(&headers, 900), Duration::ZERO);
    }
}
