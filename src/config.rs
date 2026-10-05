use crate::error::{ErrorCode, Result};
#[cfg(feature = "service")]
use crate::policy::PublicUrl;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
#[cfg(feature = "service")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

pub const MIB: u64 = 1024 * 1024;

// Operator ceilings that other components re-check on their own, so each
// boundary derives them from here instead of repeating the number.

/// Largest HTTP entity, PDF or parser input.
pub const MAX_HTTP_BODY_BYTES: u64 = 32 * MIB;
/// Most pages of one PDF.
pub const MAX_PDF_PAGES: u32 = 10_000;
/// Largest retained result report.
pub const MAX_REPORT_BYTES: u64 = 64 * MIB;
/// Longest job, which also bounds `research-curl --max-time`.
pub const MAX_JOB_SECONDS: u64 = 7200;

/// Absolute API ceilings. Operator `limits` may choose any value up to these;
/// they exist so a configuration mistake cannot admit an unbounded batch. They
/// are the only remaining compile-time bounds and mirror the `Limits` maxima.
pub const MAX_SEARCH_BATCH: usize = 128;
pub const MAX_FETCH_BATCH: usize = 1000;
pub const MAX_CRAWL_PAGES: u16 = 64;
pub const MAX_CRAWL_DEPTH: u8 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub active_jobs: usize,
    pub http_concurrency: usize,
    pub per_origin_concurrency: usize,
    pub browser_concurrency: usize,
    pub job_seconds: u64,
    pub http_seconds: u64,
    pub browser_seconds: u64,
    pub redirects: usize,
    pub retries: usize,
    pub html_bytes: u64,
    pub pdf_bytes: u64,
    pub job_bytes: u64,
    pub job_micro_usd: u64,
    pub daily_micro_usd: u64,
    pub queries: u32,
    pub documents: u32,
    pub requests: u32,
    pub pdf_pages: u32,
    pub browser_actions: u32,
    /// Concurrent tool operations admitted per job across all its connections.
    pub job_operations: usize,
    /// Concurrent client connections the RPC server serves at once.
    pub rpc_connections: usize,
    /// Pending in-flight requests allowed per connection before `capacity`.
    pub rpc_requests: usize,
    /// Maximum search queries accepted in one call (also reduced by `queries`).
    pub search_batch: usize,
    /// Maximum fetch URLs accepted in one call (also reduced by `documents`).
    pub fetch_batch: usize,
    /// Concurrent evidence reads served from the archive/store.
    pub store_reads: usize,
    /// Concurrent isolated parser (PDF/HTML) extractions.
    pub parser_concurrency: usize,
    /// Distinct request origins tracked concurrently before admission fails.
    pub http_origins: usize,
    /// Maximum bytes of one retained truncated tool result.
    pub report_bytes: u64,
    /// Lifetime of a retained truncated tool result, in seconds.
    pub report_seconds: u64,
    pub result_bytes: usize,
    /// Operator ceiling on total crawl pages per seed (including the seed). The
    /// API can only reduce this; crawling is same-origin and single-seed.
    pub crawl_pages: u32,
    /// Operator ceiling on crawl link depth from the seed; 0 fetches only seeds.
    pub crawl_depth: u32,
    /// Maximum UTF-8 bytes of saved text sent to a summarization provider per
    /// request. Longer representations are cut at a character boundary and the
    /// result is marked truncated; this bounds provider input cost.
    pub summary_input_bytes: usize,
    /// Maximum completion tokens requested from a summarization provider.
    pub summary_output_tokens: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            active_jobs: 4,
            http_concurrency: 8,
            per_origin_concurrency: 2,
            browser_concurrency: 2,
            job_seconds: 300,
            http_seconds: 30,
            browser_seconds: 60,
            redirects: 5,
            retries: 2,
            html_bytes: 8 * MIB,
            pdf_bytes: 32 * MIB,
            job_bytes: 128 * MIB,
            job_micro_usd: 500_000,
            daily_micro_usd: 5_000_000,
            queries: 8,
            documents: 20,
            requests: 512,
            pdf_pages: 200,
            browser_actions: 40,
            job_operations: 16,
            rpc_connections: 32,
            rpc_requests: 16,
            search_batch: 16,
            fetch_batch: 64,
            store_reads: 2,
            parser_concurrency: 2,
            http_origins: 4096,
            report_bytes: 16 * MIB,
            report_seconds: 300,
            result_bytes: 64 * 1024,
            crawl_pages: 16,
            crawl_depth: 2,
            summary_input_bytes: 64 * 1024,
            summary_output_tokens: 1024,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        if self.active_jobs == 0
            || self.active_jobs > 64
            || self.http_concurrency == 0
            || self.http_concurrency > 256
            || self.per_origin_concurrency == 0
            || self.per_origin_concurrency > self.http_concurrency
            || self.browser_concurrency > 16
            || self.job_seconds == 0
            || self.job_seconds > MAX_JOB_SECONDS
            || self.http_seconds == 0
            || self.browser_seconds == 0
            || self.http_seconds > self.job_seconds
            || self.browser_seconds > self.job_seconds
            || self.redirects > 20
            || self.retries > 2
            || self.html_bytes == 0
            || self.pdf_bytes == 0
            || self.html_bytes > MAX_HTTP_BODY_BYTES
            || self.pdf_bytes > MAX_HTTP_BODY_BYTES
            || self.html_bytes > self.job_bytes
            || self.pdf_bytes > self.job_bytes
            || self.job_bytes > 4096 * MIB
            || self.job_micro_usd > self.daily_micro_usd
            || self.daily_micro_usd > 1_000_000_000
            || self.queries == 0
            || self.queries > 128
            || self.documents == 0
            || self.documents > 1000
            || self.requests == 0
            || self.requests > 100_000
            || self.pdf_pages == 0
            || self.pdf_pages > MAX_PDF_PAGES
            || self.browser_actions == 0
            || self.browser_actions > 1000
            || self.job_operations == 0
            || self.job_operations > 4096
            || self.rpc_connections == 0
            || self.rpc_connections > 4096
            || self.rpc_requests == 0
            || self.rpc_requests > 1024
            || self.search_batch == 0
            || self.search_batch > MAX_SEARCH_BATCH
            || self.fetch_batch == 0
            || self.fetch_batch > MAX_FETCH_BATCH
            || self.store_reads == 0
            || self.store_reads > 64
            || self.parser_concurrency == 0
            || self.parser_concurrency > 16
            || self.http_origins == 0
            || self.http_origins > 65_536
            || !(4096..=MAX_REPORT_BYTES).contains(&self.report_bytes)
            || self.report_seconds == 0
            || self.report_seconds > 3600
            || self.crawl_pages == 0
            || self.crawl_pages > 64
            || self.crawl_depth > 5
            || !(4096..=262_144).contains(&self.result_bytes)
            || !(4096..=512 * 1024).contains(&self.summary_input_bytes)
            || !(64..=8192).contains(&self.summary_output_tokens)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privacy {
    #[default]
    Practical,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Search,
    Scrape,
    Summarize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Queries,
    Urls,
    Content,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderConfig {
    pub enable: bool,
    pub capabilities: BTreeSet<Capability>,
    pub data: BTreeSet<DataClass>,
    /// systemd credential name, never a request-selected path or an API key.
    pub credential: Option<String>,
    pub storage_rights: bool,
    /// Operator-confirmed fixed price per successful request, in micro-dollars.
    /// Absence is not a free price and cannot enable paid network work. For
    /// token-billed summarization this is the operator's per-request ceiling,
    /// settled in full on success; the bounded input/output limits make it a
    /// real bound rather than an estimate.
    pub request_micro_usd: Option<u64>,
    /// Operator-selected model identifier for a summarization provider. Never a
    /// request parameter; absent for search/scrape adapters.
    pub model: Option<String>,
    /// Operator-configured bare public HTTPS origin for a self-hosted adapter
    /// whose endpoint is not a fixed constant. It is set only by `searxng`;
    /// authentication-less providers still need no credential or price.
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    pub days: u32,
    pub bytes: u64,
    pub cache_seconds: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            days: 7,
            bytes: 2048 * MIB,
            cache_seconds: 900,
        }
    }
}

/// `User-Agent` sent on protected HTTP fetches and used as the robots product
/// token. Keep its platform and reduced Chrome version aligned with the pinned
/// Chromium browser; the real-browser fixture detects drift after pin updates.
/// The robots matcher derives `Mozilla` as the product token.
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";

/// Longest accepted `User-Agent`. A full browser identification needs more room
/// than a bare product token; the bound only keeps the value small.
pub const MAX_USER_AGENT: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RobotsConfig {
    pub user_agent: String,
    pub selected_page_error_allows: bool,
    pub cache_seconds: u64,
    pub max_bytes: usize,
}

impl Default for RobotsConfig {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.into(),
            selected_page_error_allows: true,
            cache_seconds: 3600,
            max_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadPostRule {
    pub origin: String,
    pub path: String,
    pub max_bytes: usize,
    pub operation: ReadPostOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReadPostOperation {
    ExactBody {
        sha256: String,
        content_type: String,
    },
    Graphql {
        document_sha256: String,
        operation_name: String,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePolicy {
    /// Always use the coherent neutral profile (en-US / UTC / en-US).
    #[default]
    Neutral,
    /// Pick a coherent profile from the observed VPN exit region, falling back
    /// to neutral for an unknown or absent region. Rotation is between sessions.
    ExitRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[cfg(feature = "service")]
pub struct BrowserConfig {
    pub enable: bool,
    pub sandbox: Option<crate::browser::sandbox::SandboxConfig>,
    pub executable: PathBuf,
    pub idle_seconds: u64,
    pub width: u32,
    pub height: u32,
    pub read_post_rules: Vec<ReadPostRule>,
    pub profile: ProfilePolicy,
}

#[cfg(feature = "service")]
impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            enable: false,
            sandbox: None,
            executable: "/unconfigured/chromium".into(),
            idle_seconds: 60,
            width: 1365,
            height: 768,
            read_post_rules: Vec::new(),
            profile: ProfilePolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[cfg(feature = "service")]
pub struct Config {
    pub version: u32,
    pub socket_path: PathBuf,
    pub state_directory: PathBuf,
    pub egress_socket: PathBuf,
    /// Expected Unix listener peer, not the eventual worker's process UID.
    /// A root systemd socket unit retains UID 0 across FD activation.
    pub egress_uid: Option<u32>,
    pub egress_control_file: PathBuf,
    pub allowed_client_uids: Vec<u32>,
    pub privacy: Privacy,
    pub providers: BTreeMap<String, ProviderConfig>,
    pub search_order: Vec<String>,
    pub scrape_order: Vec<String>,
    /// Summarization is a separately enabled expansion: Research is complete
    /// without it, and an empty order means no summary provider exists.
    pub summarize_order: Vec<String>,
    /// Operator-only local SearXNG transport. Never selected by a fetched URL.
    pub searxng_socket: Option<PathBuf>,
    pub limits: Limits,
    pub retention: Retention,
    pub robots: RobotsConfig,
    pub browser: BrowserConfig,
    pub workers: Option<crate::worker::WorkerConfig>,
}

#[cfg(feature = "service")]
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            socket_path: "/run/agent-research/socket".into(),
            state_directory: "/var/lib/agent-research".into(),
            egress_socket: "/run/agent-research-egress/socket".into(),
            egress_uid: None,
            egress_control_file: "/run/agent-research-egress/control/state.json".into(),
            allowed_client_uids: Vec::new(),
            privacy: Privacy::default(),
            providers: BTreeMap::new(),
            search_order: Vec::new(),
            // Empty by default: an existing search-only deployment must keep
            // validating unchanged, and no provider is enabled implicitly.
            scrape_order: Vec::new(),
            summarize_order: Vec::new(),
            searxng_socket: None,
            limits: Limits::default(),
            retention: Retention::default(),
            robots: RobotsConfig::default(),
            browser: BrowserConfig::default(),
            workers: None,
        }
    }
}

#[cfg(feature = "service")]
impl Config {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.version != 1
            || !self.socket_path.is_absolute()
            || !self.state_directory.is_absolute()
            || !self.egress_socket.is_absolute()
            || !self.egress_control_file.is_absolute()
            || self.searxng_socket.as_ref().is_some_and(|path| {
                !path.is_absolute()
                    || path
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
            })
            || self.egress_uid.is_none_or(|uid| uid == u32::MAX)
            || self.allowed_client_uids.is_empty()
            || self.retention.days == 0
            || self.retention.days > 365
            || self.retention.bytes < self.limits.pdf_bytes
            || self.retention.bytes > 1_048_576 * MIB
            || self.retention.cache_seconds > 86_400
            || self.robots.user_agent.is_empty()
            || self.robots.user_agent.len() > MAX_USER_AGENT
            // Printable ASCII including spaces, so a browser identification is
            // accepted. Control octets and DEL stay forbidden: the value is
            // placed into request headers and must not break header framing.
            || !self
                .robots
                .user_agent
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b))
            || self.robots.cache_seconds > 86_400
            || !(512 * 1024..=4 * 1024 * 1024).contains(&self.robots.max_bytes)
            || self.search_order.len() > 8
            || self.search_order.iter().collect::<BTreeSet<_>>().len() != self.search_order.len()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        const SEARCH_PROVIDERS: [&str; 3] = ["brave", "tavily", "searxng"];
        const SCRAPE_PROVIDERS: [&str; 2] = ["spider", "firecrawl"];
        const SUMMARIZE_PROVIDERS: [&str; 1] = ["openai"];
        for (name, provider) in &self.providers {
            // Only implemented adapters are accepted. The search adapters are
            // Brave, Tavily and self-hosted SearXNG; Spider and Firecrawl expose
            // Capability::Scrape; the OpenAI-compatible adapter exposes
            // Capability::Summarize. Additional adapters become available only
            // with matching code and explicit capability grants, never because an
            // environment key exists.
            let search = SEARCH_PROVIDERS.contains(&name.as_str());
            let scrape = SCRAPE_PROVIDERS.contains(&name.as_str());
            let summarize = SUMMARIZE_PROVIDERS.contains(&name.as_str());
            // Self-hosted SearXNG has no API key and no per-request tariff, so
            // it alone is exempt from the credential/price requirement. It takes
            // an operator-authored origin, validated as a bare public HTTPS
            // origin so it cannot widen the egress policy.
            let credential_less = name == "searxng";
            let configurable_endpoint = name == "searxng";
            let expected = if search {
                Capability::Search
            } else if scrape {
                Capability::Scrape
            } else {
                Capability::Summarize
            };
            if (!search && !scrape && !summarize)
                || provider
                    .capabilities
                    .iter()
                    .any(|capability| *capability != expected)
                || (provider.enable
                    && (provider.capabilities.is_empty()
                        || (!credential_less && provider.credential.is_none())
                        || (!credential_less && provider.request_micro_usd.is_none())
                        || (search && !provider.data.contains(&DataClass::Queries))
                        || (scrape
                            && (!provider.data.contains(&DataClass::Urls)
                                || !provider.data.contains(&DataClass::Content)))
                        || (summarize
                            && (!provider.data.contains(&DataClass::Content)
                                || provider.model.is_none()))))
                || (!configurable_endpoint && provider.endpoint.is_some())
                || (name == "searxng" && provider.enable
                    && (provider.endpoint.is_some() == self.searxng_socket.is_some()))
                || (configurable_endpoint
                    && provider
                        .endpoint
                        .as_deref()
                        .is_some_and(|endpoint| !public_origin(endpoint)))
                || provider
                    .request_micro_usd
                    .is_some_and(|price| price > 1_000_000_000)
                || provider
                    .credential
                    .as_ref()
                    .is_some_and(|c| !credential_name(c))
                // A model is a summarization setting only.
                || provider
                    .model
                    .as_ref()
                    .is_some_and(|model| !summarize || !model_name(model))
            {
                return Err(ErrorCode::InvalidRequest);
            }
        }
        // Once any provider is configured, all orders must only reference
        // configured providers so an operator cannot silently rank one this
        // deployment does not have. Defaults select no commercial provider. The
        // orders are pairwise disjoint: a provider serves exactly one capability.
        if self
            .search_order
            .iter()
            .any(|name| !SEARCH_PROVIDERS.contains(&name.as_str()))
            || self
                .scrape_order
                .iter()
                .any(|name| !SCRAPE_PROVIDERS.contains(&name.as_str()))
            || self
                .summarize_order
                .iter()
                .any(|name| !SUMMARIZE_PROVIDERS.contains(&name.as_str()))
            || (!self.providers.is_empty()
                && self
                    .search_order
                    .iter()
                    .chain(self.scrape_order.iter())
                    .chain(self.summarize_order.iter())
                    .any(|name| !self.providers.contains_key(name)))
            || self
                .search_order
                .iter()
                .any(|name| self.scrape_order.contains(name) || self.summarize_order.contains(name))
            || self
                .scrape_order
                .iter()
                .any(|name| self.summarize_order.contains(name))
            || self.scrape_order.len() > 8
            || self.scrape_order.iter().collect::<BTreeSet<_>>().len() != self.scrape_order.len()
            || self.summarize_order.len() > 8
            || self.summarize_order.iter().collect::<BTreeSet<_>>().len()
                != self.summarize_order.len()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        if let Some(workers) = &self.workers {
            workers.validate()?;
        }
        if self.browser.enable
            && (!self.browser.executable.is_absolute()
                || self.limits.browser_concurrency == 0
                || self.browser.idle_seconds == 0
                || self.browser.idle_seconds > self.limits.job_seconds
                || !(640..=2560).contains(&self.browser.width)
                || !(480..=1440).contains(&self.browser.height))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        if self.browser.enable {
            self.browser
                .sandbox
                .as_ref()
                .ok_or(ErrorCode::InvalidRequest)?
                .validate()?;
            crate::browser::manager::settings(self).validate()?;
        }
        for rule in &self.browser.read_post_rules {
            let target = PublicUrl::parse(&rule.origin)?;
            if target.origin() != rule.origin
                || !rule.path.starts_with('/')
                || rule.path.starts_with("//")
                || rule.path.contains(['?', '#', '\\'])
                || rule.max_bytes == 0
                || rule.max_bytes > 64 * 1024
            {
                return Err(ErrorCode::InvalidRequest);
            }
            let digest = match &rule.operation {
                ReadPostOperation::ExactBody {
                    sha256,
                    content_type,
                } => {
                    if !matches!(
                        content_type.as_str(),
                        "application/json" | "application/x-www-form-urlencoded"
                    ) {
                        return Err(ErrorCode::InvalidRequest);
                    }
                    sha256
                }
                ReadPostOperation::Graphql {
                    document_sha256,
                    operation_name,
                } => {
                    if operation_name.is_empty()
                        || operation_name.len() > 128
                        || !operation_name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return Err(ErrorCode::InvalidRequest);
                    }
                    document_sha256
                }
            };
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(ErrorCode::InvalidRequest);
            }
        }
        Ok(())
    }

    pub fn provider_allowed(&self, name: &str, capability: Capability) -> bool {
        (self.privacy != Privacy::Strict || capability == Capability::Search)
            && self.providers.get(name).is_some_and(|p| {
                p.enable
                    && p.capabilities.contains(&capability)
                    && match capability {
                        Capability::Search => p.data.contains(&DataClass::Queries),
                        // Sending the URL and storing the returned content are
                        // two separate grants; scrape needs both.
                        Capability::Scrape => {
                            p.data.contains(&DataClass::Urls)
                                && p.data.contains(&DataClass::Content)
                        }
                        Capability::Summarize => p.data.contains(&DataClass::Content),
                    }
            })
    }
}

#[cfg(feature = "service")]
fn credential_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// A self-hosted adapter endpoint is a bare public HTTPS origin: no path, port,
/// query, userinfo or fragment. The egress proxy still re-resolves the host and
/// enforces the public-address policy for every request, so this only bounds the
/// operator-authored shape and cannot widen the network boundary.
#[cfg(feature = "service")]
fn public_origin(value: &str) -> bool {
    value.starts_with("https://") && PublicUrl::parse(value).is_ok_and(|url| url.origin() == value)
}

/// Model identifiers are sent verbatim in a provider request body; keep them to
/// a printable, whitespace-free ASCII token so the body cannot be malformed.
pub fn model_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/'))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    pub socket_path: PathBuf,
    /// Root-authored readiness/exit generation; unavailable means fail closed.
    pub control_file: PathBuf,
    pub allowed_peer_uids: Vec<u32>,
    pub vpn_interface: String,
    pub resolvers: Vec<IpAddr>,
    pub denied_networks: Vec<IpNet>,
    pub max_connections: usize,
    pub connection_seconds: u64,
    pub connection_bytes: u64,
}

impl EgressConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.socket_path.is_absolute()
            || !self.control_file.is_absolute()
            || self.allowed_peer_uids.is_empty()
            || self.allowed_peer_uids.contains(&0)
            || self.vpn_interface.is_empty()
            || self.vpn_interface.len() > 15
            || !self
                .vpn_interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            || matches!(self.vpn_interface.as_str(), "lo" | "all" | "default")
            || self.resolvers.is_empty()
            || self.resolvers.len() > 4
            || self
                .resolvers
                .iter()
                .any(|ip| !crate::policy::public_ip(*ip, &[]))
            || !(1..=128).contains(&self.max_connections)
            || !(1..=300).contains(&self.connection_seconds)
            || self.connection_bytes == 0
            || self.connection_bytes > 512 * MIB
            || self.denied_networks.len() > 1024
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "service"))]
mod tests {
    use super::*;

    fn configured() -> Config {
        Config {
            allowed_client_uids: vec![1001],
            egress_uid: Some(1002),
            ..Config::default()
        }
    }

    #[test]
    fn egress_listener_identity_is_explicit_and_allows_root_activation() {
        let mut config = configured();
        config.egress_uid = None;
        assert!(config.validate().is_err());
        config.egress_uid = Some(0);
        config.validate().unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(encoded["egress_uid"], 0);
        let decoded: Config = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.egress_uid, Some(0));
        config.egress_uid = Some(u32::MAX);
        assert!(config.validate().is_err());
    }

    #[test]
    fn browser_profile_policy_defaults_to_neutral_and_round_trips() {
        // Older configs without a `profile` field stay valid and mean neutral.
        let defaulted: BrowserConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted.profile, ProfilePolicy::Neutral);
        let mut config = configured();
        config.browser.profile = ProfilePolicy::ExitRegion;
        config.validate().unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(encoded["browser"]["profile"], "exit_region");
        let decoded: Config = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.browser.profile, ProfilePolicy::ExitRegion);
    }

    #[test]
    fn default_robots_user_agent_is_a_valid_header_value() {
        // The shipped default is a full browser identification (spaces, longer
        // than a bare product token), so validation must accept it while still
        // rejecting over-long values and control octets.
        let config = configured();
        assert_eq!(config.robots.user_agent, DEFAULT_USER_AGENT);
        config.validate().unwrap();
        let mut too_long = configured();
        too_long.robots.user_agent = "a".repeat(MAX_USER_AGENT + 1);
        assert!(too_long.validate().is_err());
        let mut framed = configured();
        framed.robots.user_agent = format!("{DEFAULT_USER_AGENT}\r\nX-Evil: 1");
        assert!(framed.validate().is_err());
        let mut empty = configured();
        empty.robots.user_agent.clear();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn defaults_do_not_select_a_provider() {
        let config = configured();
        config.validate().unwrap();
        assert!(config.providers.is_empty());
        assert!(config.search_order.is_empty());
        assert!(config.scrape_order.is_empty());
        assert!(config.summarize_order.is_empty());
    }

    #[test]
    fn credentials_alone_never_enable_a_provider() {
        let mut config = configured();
        config.providers.insert(
            "brave".into(),
            ProviderConfig {
                endpoint: None,
                credential: Some("brave".into()),
                ..ProviderConfig::default()
            },
        );
        config.validate().unwrap();
        assert!(!config.provider_allowed("brave", Capability::Search));
    }

    #[test]
    fn explicit_provider_requires_capability_and_credential() {
        let mut config = configured();
        config.providers.insert(
            "brave".into(),
            ProviderConfig {
                endpoint: None,
                enable: true,
                ..ProviderConfig::default()
            },
        );
        assert!(config.validate().is_err());
        let provider = config.providers.get_mut("brave").unwrap();
        provider.credential = Some("brave".into());
        provider.capabilities.insert(Capability::Search);
        provider.data.insert(DataClass::Queries);
        provider.request_micro_usd = Some(5000);
        config.validate().unwrap();
        assert!(config.provider_allowed("brave", Capability::Search));
        assert!(!config.provider_allowed("brave", Capability::Scrape));
    }

    #[test]
    fn tavily_is_search_only_and_search_order_must_be_configured() {
        let mut config = configured();
        config.providers.insert(
            "tavily".into(),
            ProviderConfig {
                endpoint: None,
                enable: true,
                capabilities: [Capability::Search].into(),
                data: [DataClass::Queries].into(),
                credential: Some("tavily".into()),
                request_micro_usd: Some(8000),
                ..ProviderConfig::default()
            },
        );
        config.search_order = vec!["tavily".into()];
        config.validate().unwrap();
        assert!(config.provider_allowed("tavily", Capability::Search));
        assert!(!config.provider_allowed("tavily", Capability::Scrape));
        // Unknown names and names absent from the provider map are rejected.
        config.search_order = vec!["spider".into()];
        assert!(config.validate().is_err());
        config.search_order = vec!["brave".into()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn searxng_is_credential_less_but_needs_a_public_origin() {
        let mut config = configured();
        config.providers.insert(
            "searxng".into(),
            ProviderConfig {
                endpoint: Some("https://search.example.org".into()),
                enable: true,
                capabilities: [Capability::Search].into(),
                data: [DataClass::Queries].into(),
                ..ProviderConfig::default()
            },
        );
        config.search_order = vec!["searxng".into()];
        config.validate().unwrap();
        assert!(config.provider_allowed("searxng", Capability::Search));
        assert!(!config.provider_allowed("searxng", Capability::Scrape));
        // A non-HTTPS, local, path-bearing, port-shifted or private origin is
        // rejected before any I/O; a missing origin is rejected too.
        for bad in [
            "http://search.example.org",
            "https://localhost",
            "https://search.example.org/prefix",
            "https://search.example.org:8443",
            "https://10.0.0.1",
        ] {
            let provider = config.providers.get_mut("searxng").unwrap();
            provider.endpoint = Some(bad.into());
            assert!(config.validate().is_err(), "endpoint accepted: {bad}");
        }
        config.providers.get_mut("searxng").unwrap().endpoint = None;
        assert!(config.validate().is_err());
        // A fixed-endpoint adapter may not smuggle a self-hosted origin.
        let mut other = configured();
        other.providers.insert(
            "brave".into(),
            ProviderConfig {
                endpoint: Some("https://search.example.org".into()),
                enable: true,
                capabilities: [Capability::Search].into(),
                data: [DataClass::Queries].into(),
                credential: Some("brave".into()),
                request_micro_usd: Some(5000),
                ..ProviderConfig::default()
            },
        );
        assert!(other.validate().is_err());
    }

    #[test]
    fn invalid_limits_and_unknown_config_fail_before_io() {
        assert!(serde_json::from_str::<Config>(r#"{"public_only":false}"#).is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"job_micro_usd":-1}"#).is_err());
        let mut config = configured();
        config.limits.job_micro_usd = u64::MAX;
        assert!(config.validate().is_err());
        config = configured();
        config
            .providers
            .insert("brvae".into(), ProviderConfig::default());
        assert!(config.validate().is_err());
    }

    #[test]
    fn crawl_limits_are_bounded_and_backward_compatible() {
        // Older configs without crawl fields stay valid and get the defaults.
        let defaulted: Limits = serde_json::from_str("{}").unwrap();
        assert_eq!((defaulted.crawl_pages, defaulted.crawl_depth), (16, 2));
        let mut config = configured();
        config.validate().unwrap();
        for (pages, depth, valid) in [
            (0u32, 0u32, false),
            (64, 5, true),
            (65, 0, false),
            (1, 6, false),
        ] {
            config.limits.crawl_pages = pages;
            config.limits.crawl_depth = depth;
            assert_eq!(config.validate().is_ok(), valid, "{pages}/{depth}");
        }
    }

    #[test]
    fn service_caps_are_configurable_and_bounded() {
        // Defaults reproduce the previously hard-coded values, so an existing
        // config keeps its exact behavior.
        let defaults = configured();
        defaults.validate().unwrap();
        assert_eq!(defaults.limits.job_operations, 16);
        assert_eq!(defaults.limits.rpc_connections, 32);
        assert_eq!(defaults.limits.rpc_requests, 16);
        assert_eq!(defaults.limits.search_batch, 16);
        assert_eq!(defaults.limits.fetch_batch, 64);
        assert_eq!(defaults.limits.store_reads, 2);
        assert_eq!(defaults.limits.parser_concurrency, 2);
        assert_eq!(defaults.limits.http_origins, 4096);
        assert_eq!(defaults.limits.report_bytes, 16 * MIB);
        assert_eq!(defaults.limits.report_seconds, 300);

        for mutate in [
            (|l: &mut Limits| l.job_operations = 0) as fn(&mut Limits),
            |l| l.job_operations = 4097,
            |l| l.rpc_connections = 0,
            |l| l.rpc_requests = 0,
            |l| l.search_batch = 0,
            |l| l.search_batch = MAX_SEARCH_BATCH + 1,
            |l| l.fetch_batch = 0,
            |l| l.fetch_batch = MAX_FETCH_BATCH + 1,
            |l| l.store_reads = 0,
            |l| l.parser_concurrency = 0,
            |l| l.parser_concurrency = 17,
            |l| l.http_origins = 0,
            |l| l.http_origins = 65_537,
            |l| l.report_bytes = 4095,
            |l| l.report_bytes = MAX_REPORT_BYTES + 1,
            |l| l.report_seconds = 0,
            |l| l.report_seconds = 3601,
        ] {
            let mut broken = configured();
            mutate(&mut broken.limits);
            assert!(broken.validate().is_err());
        }

        // The maxima are accepted and remain operator-settable.
        let mut maxima = configured();
        maxima.limits.job_operations = 4096;
        maxima.limits.rpc_connections = 4096;
        maxima.limits.rpc_requests = 1024;
        maxima.limits.search_batch = MAX_SEARCH_BATCH;
        maxima.limits.fetch_batch = MAX_FETCH_BATCH;
        maxima.limits.store_reads = 64;
        maxima.limits.parser_concurrency = 16;
        maxima.limits.http_origins = 65_536;
        maxima.limits.report_bytes = MAX_REPORT_BYTES;
        maxima.limits.report_seconds = 3600;
        maxima.validate().unwrap();
    }

    #[test]
    fn credential_paths_are_not_a_configuration_escape() {
        for name in ["../key", "/etc/shadow", "key\nvalue", "", "a.b"] {
            assert!(!credential_name(name));
        }
    }

    fn scrape_provider() -> ProviderConfig {
        ProviderConfig {
            endpoint: None,
            enable: true,
            capabilities: [Capability::Scrape].into(),
            data: [DataClass::Urls, DataClass::Content].into(),
            credential: Some("firecrawl".into()),
            request_micro_usd: Some(5000),
            ..ProviderConfig::default()
        }
    }

    #[test]
    fn scrape_provider_requires_both_urls_and_content_grants() {
        let mut config = configured();
        config.search_order = Vec::new();
        config
            .providers
            .insert("firecrawl".into(), scrape_provider());
        config.scrape_order = vec!["firecrawl".into()];
        config.validate().unwrap();
        assert!(config.provider_allowed("firecrawl", Capability::Scrape));
        assert!(!config.provider_allowed("firecrawl", Capability::Search));
        // Sending the URL grant alone is not enough to store returned content.
        config
            .providers
            .get_mut("firecrawl")
            .unwrap()
            .data
            .remove(&DataClass::Content);
        assert!(config.validate().is_err());
        // A disabled provider keeps validating but is never eligible.
        config = configured();
        config.search_order = Vec::new();
        config.providers.insert(
            "firecrawl".into(),
            ProviderConfig {
                endpoint: None,
                enable: false,
                ..scrape_provider()
            },
        );
        config.scrape_order = vec!["firecrawl".into()];
        config.validate().unwrap();
        assert!(!config.provider_allowed("firecrawl", Capability::Scrape));
    }

    #[test]
    fn scrape_and_search_orders_stay_disjoint_and_configured() {
        let mut config = configured();
        config
            .providers
            .insert("firecrawl".into(), scrape_provider());
        config.scrape_order = vec!["firecrawl".into()];
        // A scrape provider can never be ranked for search.
        config.search_order = vec!["firecrawl".into()];
        assert!(config.validate().is_err());
        config.search_order = Vec::new();
        // A search provider can never be ranked for scrape.
        config.scrape_order = vec!["brave".into()];
        assert!(config.validate().is_err());
        // Unknown and unconfigured names are rejected.
        config.scrape_order = vec!["unknown".into()];
        assert!(config.validate().is_err());
        config.scrape_order = vec!["spider".into()];
        assert!(config.validate().is_err());
        config.scrape_order = vec!["firecrawl".into()];
        config.validate().unwrap();
    }

    #[test]
    fn spider_is_a_scrape_provider_and_never_ranked_for_search() {
        let mut config = configured();
        config.search_order = Vec::new();
        config.providers.insert(
            "spider".into(),
            ProviderConfig {
                endpoint: None,
                credential: Some("spider".into()),
                ..scrape_provider()
            },
        );
        config.scrape_order = vec!["spider".into()];
        config.validate().unwrap();
        assert!(config.provider_allowed("spider", Capability::Scrape));
        assert!(!config.provider_allowed("spider", Capability::Search));
        // A scrape provider can never be ranked for search.
        config.search_order = vec!["spider".into()];
        assert!(config.validate().is_err());
        // Missing the content grant invalidates the provider entirely.
        let mut config = configured();
        config.search_order = Vec::new();
        config.providers.insert(
            "spider".into(),
            ProviderConfig {
                endpoint: None,
                credential: Some("spider".into()),
                ..scrape_provider()
            },
        );
        config
            .providers
            .get_mut("spider")
            .unwrap()
            .data
            .remove(&DataClass::Content);
        config.scrape_order = vec!["spider".into()];
        assert!(config.validate().is_err());
    }

    fn summarize_provider() -> ProviderConfig {
        ProviderConfig {
            endpoint: None,
            enable: true,
            capabilities: [Capability::Summarize].into(),
            data: [DataClass::Content].into(),
            credential: Some("openai".into()),
            request_micro_usd: Some(20_000),
            model: Some("gpt-4o-mini".into()),
            ..ProviderConfig::default()
        }
    }

    #[test]
    fn summarization_is_separately_enabled_and_needs_content_model_and_price() {
        // Older configs without `summarize_order`, `model` or the summary
        // limits stay valid and mean "no summarization".
        let defaulted: Config =
            serde_json::from_str(r#"{"allowed_client_uids":[1001],"egress_uid":1002}"#).unwrap();
        assert!(defaulted.summarize_order.is_empty());
        assert_eq!(defaulted.limits.summary_input_bytes, 64 * 1024);
        assert_eq!(defaulted.limits.summary_output_tokens, 1024);
        defaulted.validate().unwrap();
        let mut config = configured();
        config.search_order = Vec::new();
        config
            .providers
            .insert("openai".into(), summarize_provider());
        config.summarize_order = vec!["openai".into()];
        config.validate().unwrap();
        assert!(config.provider_allowed("openai", Capability::Summarize));
        assert!(!config.provider_allowed("openai", Capability::Search));
        assert!(!config.provider_allowed("openai", Capability::Scrape));
        // Strict privacy disables external analysis entirely.
        config.privacy = Privacy::Strict;
        config.validate().unwrap();
        assert!(!config.provider_allowed("openai", Capability::Summarize));
        config.privacy = Privacy::Practical;
        // The content grant, a model and a price ceiling are all required.
        for mutate in [
            (|p: &mut ProviderConfig| {
                p.data.clear();
            }) as fn(&mut ProviderConfig),
            |p| p.model = None,
            |p| p.request_micro_usd = None,
            |p| p.model = Some("bad model\n".into()),
            |p| {
                p.capabilities = [Capability::Search].into();
            },
        ] {
            let mut broken = config.clone();
            mutate(broken.providers.get_mut("openai").unwrap());
            assert!(broken.validate().is_err());
        }
        // A model is never accepted on a search or scrape adapter, and the
        // summarize adapter is never ranked for search or scrape.
        let mut wrong = configured();
        wrong.providers.insert(
            "brave".into(),
            ProviderConfig {
                endpoint: None,
                model: Some("gpt-4o-mini".into()),
                credential: Some("brave".into()),
                ..ProviderConfig::default()
            },
        );
        assert!(wrong.validate().is_err());
        let mut ranked = config.clone();
        ranked.search_order = vec!["openai".into()];
        assert!(ranked.validate().is_err());
        ranked = config.clone();
        ranked.scrape_order = vec!["openai".into()];
        assert!(ranked.validate().is_err());
        ranked = config.clone();
        ranked.summarize_order = vec!["brave".into()];
        assert!(ranked.validate().is_err());
        // A disabled provider keeps validating but is never eligible.
        config.providers.get_mut("openai").unwrap().enable = false;
        config.validate().unwrap();
        assert!(!config.provider_allowed("openai", Capability::Summarize));
        // Summary bounds are validated like other limits.
        let mut limits = configured();
        limits.limits.summary_input_bytes = 1024;
        assert!(limits.validate().is_err());
        limits = configured();
        limits.limits.summary_output_tokens = 0;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn strict_privacy_disables_scrape_but_keeps_search() {
        let mut config = configured();
        config.search_order = Vec::new();
        config
            .providers
            .insert("firecrawl".into(), scrape_provider());
        config.scrape_order = vec!["firecrawl".into()];
        config.validate().unwrap();
        assert!(config.provider_allowed("firecrawl", Capability::Scrape));
        config.privacy = Privacy::Strict;
        config.validate().unwrap();
        assert!(!config.provider_allowed("firecrawl", Capability::Scrape));
    }
}
