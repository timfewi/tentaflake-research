//! Pooled retrieval through an explicit proxy. The deployment namespace removes
//! every direct route; the private relay is never an MCP or host-facing API.

use crate::budget::{Charge, Ledger};
use crate::config::Limits;
use crate::diagnostics::{self, Component, Event};
use crate::error::{ErrorCode, Result};
use crate::policy::{PublicUrl, limited_referrer, validate_origin_header};
use crate::socket::{authorized_peer, validate_socket_path};
use futures_util::TryStreamExt;
use reqwest::header::{HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, ORIGIN, REFERER};
use std::collections::HashMap;
use std::error::Error as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct ProxyRelay {
    url: String,
    task: JoinHandle<()>,
    stop: CancellationToken,
}

impl ProxyRelay {
    pub async fn start(socket: &Path, expected_uid: u32, maximum: usize) -> Result<Self> {
        if !(1..=256).contains(&maximum) {
            return Err(ErrorCode::InvalidRequest);
        }
        validate_socket_path(socket)?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| ErrorCode::EgressUnavailable)?;
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .map_err(|_| ErrorCode::EgressUnavailable)?
        );
        let socket: PathBuf = socket.into();
        let stop = CancellationToken::new();
        let cancelled = stop.clone();
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(maximum));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = cancelled.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((mut client, _)) = accepted else {
                            diagnostics::emit(Component::Service, Event::RelayAcceptFailed);
                            break;
                        };
                        let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                        let socket = socket.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            let mut proxy = match timeout(Duration::from_secs(5), UnixStream::connect(socket)).await {
                                Err(_) => {
                                    diagnostics::emit(Component::Service, Event::RelayConnectTimeout);
                                    return;
                                }
                                Ok(Err(_)) => {
                                    diagnostics::emit(Component::Service, Event::RelayConnectFailed);
                                    return;
                                }
                                Ok(Ok(proxy)) => proxy,
                            };
                            if authorized_peer(&proxy, &[expected_uid]).is_err() {
                                diagnostics::emit(Component::Service, Event::RelayPeerUnauthorized);
                                return;
                            }
                            match timeout(Duration::from_secs(300), tokio::io::copy_bidirectional(&mut client, &mut proxy)).await {
                                Err(_) => diagnostics::emit(Component::Service, Event::RelayTransportTimeout),
                                Ok(Err(_)) => diagnostics::emit(Component::Service, Event::RelayTransportFailed),
                                Ok(Ok(_)) => (),
                            }
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => (),
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self { url, task, stop })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn close(self) {
        self.stop.cancel();
        // JoinHandle is retained by Drop; awaiting through a mutable borrow
        // allows orderly relay cleanup without moving out of a Drop type.
        let mut this = self;
        let _ = (&mut this.task).await;
    }
}

impl Drop for ProxyRelay {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

pub struct ProtectedHttp {
    client: reqwest::Client,
    searxng_client: Option<reqwest::Client>,
    global: Arc<Semaphore>,
    origins: Mutex<HashMap<String, Weak<Semaphore>>>,
    limits: Limits,
    ledger: Arc<Ledger>,
    _relay: ProxyRelay,
}

pub struct HttpRequest {
    pub target: PublicUrl,
    /// Service-authored headers. Callers must never deserialize arbitrary headers
    /// from an MCP request or copy them from source material.
    pub headers: HeaderMap,
    pub max_bytes: u64,
    pub micro_usd: u64,
    /// Set only by adapters whose billing contract excludes HTTP error responses.
    pub errors_are_unbilled: bool,
    /// Search-provider request: consumes one search-query slot. Model judgment,
    /// summarization and document fetches only consume their other budgets.
    pub query: bool,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct BrowserRequest<'a> {
    pub request: crate::browser::wire::HttpRequest,
    pub rules: &'a [crate::config::ReadPostRule],
    pub max_bytes: u64,
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Dedicated local search capability, never inferred from a request URL.
    async fn searxng(
        &self,
        _owner: u32,
        _job: Uuid,
        _request: HttpRequest,
        _stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        Err(ErrorCode::ProviderUnavailable)
    }
    async fn get(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse>;

    /// Fixed-body POST for provider adapters. The default denies it so fixtures
    /// that only implement `get` stay non-POST-capable and cannot be widened by
    /// accident. Adapters supply a service-authored body, never tool input.
    async fn post(
        &self,
        _owner: u32,
        _job: Uuid,
        _request: HttpRequest,
        _body: Vec<u8>,
        _stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        Err(ErrorCode::ProviderUnavailable)
    }

    /// Worker input is untrusted. Recheck the operator's read rules at the
    /// service boundary before admitting any browser request.
    async fn browser(
        &self,
        owner: u32,
        job: Uuid,
        request: BrowserRequest<'_>,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let checked = crate::browser::request::check(&request.request, request.rules)?;
        if checked.method != reqwest::Method::GET {
            return Err(ErrorCode::ProviderUnavailable);
        }
        self.get(
            owner,
            job,
            browser_request(checked.target, checked.headers, request.max_bytes),
            stop,
        )
        .await
    }
}

/// Rustls client configuration with pinned public roots and explicit ALPN so
/// the pinned HTTP stack offers HTTP/2 (h2) with HTTP/1.1 fallback over the
/// mandatory egress relay. A preconfigured backend does not add this itself.
fn tls_config() -> Result<rustls::ClientConfig> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ErrorCode::InvalidRequest)?
    .with_root_certificates(rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

fn browser_request(target: PublicUrl, headers: HeaderMap, max_bytes: u64) -> HttpRequest {
    HttpRequest {
        target,
        headers,
        max_bytes,
        micro_usd: 0,
        errors_are_unbilled: false,
        query: false,
    }
}

fn restrict_request_metadata(request: &mut HttpRequest) -> Result<()> {
    // Enforce the same floor at the last service boundary before an HTTPS
    // tunnel hides headers from the egress proxy.
    // Validators can link separate visits; Research does not issue conditional
    // requests, and Chromium's own cache is disabled for controlled targets.
    request.headers.remove(IF_NONE_MATCH);
    request.headers.remove(IF_MODIFIED_SINCE);
    if request.headers.get_all(REFERER).iter().nth(1).is_some()
        || request.headers.get_all(ORIGIN).iter().nth(1).is_some()
    {
        return Err(ErrorCode::InvalidRequest);
    }
    if let Some(value) = request.headers.get(REFERER) {
        let raw = value.to_str().map_err(|_| ErrorCode::InvalidRequest)?;
        match limited_referrer(raw, &request.target)? {
            Some(value) => {
                request.headers.insert(
                    REFERER,
                    HeaderValue::from_str(&value).map_err(|_| ErrorCode::InvalidRequest)?,
                );
            }
            None => {
                request.headers.remove(REFERER);
            }
        }
    }
    if let Some(value) = request.headers.get(ORIGIN) {
        validate_origin_header(value.to_str().map_err(|_| ErrorCode::InvalidRequest)?)?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl Transport for ProtectedHttp {
    async fn searxng(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        if request.target.origin() != "http://searxng.invalid"
            || request.target.url().path() != "/search"
            || !request.query
            || request.micro_usd != 0
            || request.headers.keys().any(|name| name != "accept")
        {
            return Err(ErrorCode::PolicyDenied);
        }
        self.execute(
            owner,
            job,
            request,
            (reqwest::Method::GET, Vec::new(), true),
            stop,
        )
        .await
    }
    async fn get(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        ProtectedHttp::get(self, owner, job, request, stop).await
    }

    async fn post(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        body: Vec<u8>,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        self.execute(
            owner,
            job,
            request,
            (reqwest::Method::POST, body, false),
            stop,
        )
        .await
    }

    async fn browser(
        &self,
        owner: u32,
        job: Uuid,
        request: BrowserRequest<'_>,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let checked = crate::browser::request::check(&request.request, request.rules)?;
        self.execute(
            owner,
            job,
            browser_request(checked.target, checked.headers, request.max_bytes),
            (checked.method, checked.body, false),
            stop,
        )
        .await
    }
}

impl ProtectedHttp {
    pub async fn new(
        socket: &Path,
        expected_uid: u32,
        limits: Limits,
        ledger: Arc<Ledger>,
        user_agent: &str,
    ) -> Result<Self> {
        limits.validate()?;
        let relay = ProxyRelay::start(socket, expected_uid, limits.http_concurrency + 4).await?;
        let tls = tls_config()?;
        let proxy = reqwest::Proxy::all(relay.url()).map_err(|_| ErrorCode::InvalidRequest)?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(limits.http_seconds))
            .pool_idle_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(limits.per_origin_concurrency)
            .user_agent(user_agent)
            .build()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        Ok(Self {
            client,
            searxng_client: None,
            global: Arc::new(Semaphore::new(limits.http_concurrency)),
            origins: Mutex::new(HashMap::new()),
            limits,
            ledger,
            _relay: relay,
        })
    }

    pub fn with_searxng_socket(mut self, socket: Option<&Path>) -> Result<Self> {
        if let Some(socket) = socket {
            validate_socket_path(socket)?;
            self.searxng_client = Some(
                reqwest::Client::builder()
                    .tls_backend_preconfigured(tls_config()?)
                    .unix_socket(socket.to_path_buf())
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .retry(reqwest::retry::never())
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(self.limits.http_seconds))
                    .build()
                    .map_err(|_| ErrorCode::InvalidRequest)?,
            );
        }
        Ok(self)
    }

    async fn permits(
        &self,
        target: &PublicUrl,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let origin = {
            let mut origins = self.origins.lock().map_err(|_| ErrorCode::Capacity)?;
            origins.retain(|_, weak| weak.strong_count() != 0);
            let key = target.origin();
            // The table limits distinct active origins, not another request
            // sharing an existing origin's concurrency semaphore.
            if origins.len() >= self.limits.http_origins && !origins.contains_key(&key) {
                return Err(ErrorCode::Capacity);
            }
            let entry = origins.entry(key).or_default();
            if let Some(semaphore) = entry.upgrade() {
                semaphore
            } else {
                let semaphore = Arc::new(Semaphore::new(self.limits.per_origin_concurrency));
                *entry = Arc::downgrade(&semaphore);
                semaphore
            }
        };
        // Waiting for an origin does not consume scarce global capacity.
        let origin = origin
            .acquire_owned()
            .await
            .map_err(|_| ErrorCode::Cancelled)?;
        let global = self
            .global
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ErrorCode::Cancelled)?;
        Ok((origin, global))
    }

    /// One attempt, no automatic retry or redirect. Every subsequent attempt
    /// must re-enter admission and policy checks with its own reservation.
    pub async fn get(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        self.execute(
            owner,
            job,
            request,
            (reqwest::Method::GET, Vec::new(), false),
            stop,
        )
        .await
    }

    async fn execute(
        &self,
        owner: u32,
        job: Uuid,
        mut request: HttpRequest,
        payload: (reqwest::Method, Vec<u8>, bool),
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        if request.max_bytes == 0
            || request.max_bytes > self.limits.pdf_bytes.max(self.limits.html_bytes)
            || request.headers.len() > 16
        {
            return Err(ErrorCode::InvalidRequest);
        }
        restrict_request_metadata(&mut request)?;
        let job_state = self.ledger.get(owner, job)?;
        let remaining = job_state.deadline_at - chrono::Utc::now().timestamp();
        if remaining <= 0 {
            return Err(ErrorCode::JobClosed);
        }
        let deadline =
            Instant::now() + Duration::from_secs((remaining as u64).min(self.limits.http_seconds));
        let (method, outgoing, local) = payload;
        let client = if local {
            self.searxng_client
                .as_ref()
                .ok_or(ErrorCode::ProviderUnavailable)?
        } else {
            &self.client
        };
        let work = async {
            let outgoing_bytes = outgoing.len() as u64;
            let _permits = self.permits(&request.target).await?;
            let mut reservation = self.ledger.reserve_up_to_bytes(
                owner,
                job,
                Charge {
                    // One look-ahead byte detects overflow without reading the rest.
                    bytes: request.max_bytes + 1 + outgoing_bytes,
                    micro_usd: request.micro_usd,
                    requests: 1,
                    queries: u32::from(request.query),
                    ..Charge::default()
                },
                outgoing_bytes + 2,
            )?;
            let response_maximum = reservation.reserved_bytes() - outgoing_bytes - 1;
            let response = client
                .request(method, request.target.request_url())
                .headers(request.headers)
                .body(outgoing)
                .send()
                .await
                .map_err(|error| {
                    if error.is_timeout() {
                        diagnostics::emit(Component::Service, Event::TransportTimeout);
                        ErrorCode::Timeout
                    } else if error_chain_contains::<rustls::Error>(&error) {
                        diagnostics::emit(Component::Service, Event::TransportTlsFailed);
                        ErrorCode::EgressUnavailable
                    } else if error.is_connect() {
                        diagnostics::emit(Component::Service, Event::TransportConnectFailed);
                        ErrorCode::EgressUnavailable
                    } else if error.is_body() {
                        diagnostics::emit(Component::Service, Event::TransportRequestBodyFailed);
                        ErrorCode::EgressUnavailable
                    } else if error.is_decode() {
                        diagnostics::emit(Component::Service, Event::TransportDecodeFailed);
                        ErrorCode::EgressUnavailable
                    } else if error.is_request() {
                        diagnostics::emit(Component::Service, Event::TransportRequestFailed);
                        ErrorCode::EgressUnavailable
                    } else {
                        diagnostics::emit(Component::Service, Event::TransportFailed);
                        ErrorCode::EgressUnavailable
                    }
                })?;
            let status = response.status().as_u16();
            let cost = if request.micro_usd == 0 || (request.errors_are_unbilled && status >= 400) {
                Some(0)
            } else if (200..300).contains(&status) {
                Some(request.micro_usd)
            } else {
                None
            };
            reservation.remember_cost(cost);
            let headers = response.headers().clone();
            let media = headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let maximum = if media.starts_with("text/") || media == "application/xhtml+xml" {
                response_maximum.min(self.limits.html_bytes)
            } else {
                response_maximum
            };
            let stream = response
                .bytes_stream()
                .map_err(|_| std::io::Error::other("upstream body failed"));
            let mut reader = tokio_util::io::StreamReader::new(stream).take(maximum + 1);
            let mut body = Vec::new();
            let body_result = reader.read_to_end(&mut body).await;
            // Successful fixed-price provider responses have a known charge.
            // Error responses keep their hold unless that provider proves zero.
            if body_result.is_err() {
                // The remainder of the reserved bytes/cost remains conservative
                // when a stream terminates unexpectedly (Reservation::drop).
                return Err(ErrorCode::InvalidResponse);
            }
            reservation.finish(body.len() as u64 + outgoing_bytes, cost)?;
            if body.len() as u64 > maximum {
                return Err(ErrorCode::SizeLimit);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        };
        tokio::select! {
            biased;
            _ = stop.cancelled() => Err(ErrorCode::Cancelled),
            result = timeout_at(deadline, work) => result.unwrap_or(Err(ErrorCode::Timeout)),
        }
    }
}

fn error_chain_contains<T: std::error::Error + 'static>(error: &reqwest::Error) -> bool {
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.downcast_ref::<T>().is_some() {
            return true;
        }
        source = cause.source();
    }
    false
}

/// Honor delta-seconds and HTTP-date. Values beyond the remaining deadline are
/// returned as None, so callers report throttling instead of retrying early.
pub fn retry_after(value: &str, maximum: Duration) -> Option<Duration> {
    let seconds = if let Ok(seconds) = value.trim().parse::<u64>() {
        seconds
    } else {
        let instant = chrono::DateTime::parse_from_rfc2822(value.trim()).ok()?;
        (instant.timestamp() - chrono::Utc::now().timestamp()).max(0) as u64
    };
    let delay = Duration::from_secs(seconds);
    (delay <= maximum).then_some(delay)
}

/// A later Retry-After value must not be hidden by an earlier, shorter one.
/// Invalid or over-budget values prevent automatic retry.
pub fn retry_after_headers(headers: &HeaderMap, maximum: Duration) -> Option<Duration> {
    let mut longest = None;
    for value in headers.get_all("retry-after").iter() {
        let delay = retry_after(value.to_str().ok()?, maximum)?;
        longest = Some(longest.map_or(delay, |current: Duration| current.max(delay)));
    }
    longest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::RequestedLimits;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pinned_tls_config_advertises_http2_alpn_with_http11_fallback() {
        let tls = tls_config().unwrap();
        assert_eq!(
            tls.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    async fn fixture(
        maximum: usize,
        response: &'static [u8],
        synchronize: bool,
    ) -> (
        tempfile::TempDir,
        Arc<ProtectedHttp>,
        Arc<Ledger>,
        JoinHandle<Vec<String>>,
    ) {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("egress.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(if synchronize {
            maximum
        } else {
            1
        }));
        let server = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..maximum {
                let (stream, _) = listener.accept().await.unwrap();
                let barrier = barrier.clone();
                tasks.spawn(async move {
                    let mut stream = BufReader::new(stream);
                    let mut request = String::new();
                    loop {
                        let mut line = String::new();
                        stream.read_line(&mut line).await.unwrap();
                        request.push_str(&line);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let length = request
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    assert!(length <= crate::browser::request::MAX_BODY);
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).await.unwrap();
                    request.push_str(std::str::from_utf8(&body).unwrap());
                    timeout(Duration::from_secs(3), barrier.wait())
                        .await
                        .unwrap();
                    stream.get_mut().write_all(response).await.unwrap();
                    request
                });
            }
            let mut requests = Vec::new();
            while let Some(result) = tasks.join_next().await {
                requests.push(result.unwrap());
            }
            requests
        });
        let ledger = Ledger::open(&root.path().join("ledger.sqlite"), Limits::default()).unwrap();
        let client = ProtectedHttp::new(
            &socket,
            rustix::process::getuid().as_raw(),
            Limits::default(),
            ledger.clone(),
            crate::config::DEFAULT_USER_AGENT,
        )
        .await
        .unwrap();
        (root, Arc::new(client), ledger, server)
    }

    fn request() -> HttpRequest {
        HttpRequest {
            target: PublicUrl::parse("http://example.com/?signed=a%2Fb&z=1").unwrap(),
            headers: HeaderMap::new(),
            max_bytes: 64,
            micro_usd: 0,
            errors_are_unbilled: false,
            query: false,
        }
    }

    #[tokio::test]
    async fn full_origin_table_still_admits_existing_origin() {
        let (_root, mut http, _ledger, server) =
            fixture(1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false).await;
        Arc::get_mut(&mut http).unwrap().limits.http_origins = 1;
        let first_origin = PublicUrl::parse("https://example.com/one").unwrap();
        let other_origin = PublicUrl::parse("https://other.example/two").unwrap();
        let first = http.permits(&first_origin).await.unwrap();
        let same = http.permits(&first_origin).await.unwrap();
        assert!(matches!(
            http.permits(&other_origin).await,
            Err(ErrorCode::Capacity)
        ));
        drop(first);
        drop(same);
        assert!(http.permits(&other_origin).await.is_ok());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn default_browser_user_agent_reaches_the_upstream_unchanged() {
        // The shipped default is a full browser identification with spaces and
        // punctuation. It must survive config validation, the proxy relay and
        // reqwest's header encoding byte-for-byte, because robots matching and
        // remote identification depend on the exact value.
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            false,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        http.get(1001, job.id, request(), &CancellationToken::new())
            .await
            .unwrap();
        let sent = server.await.unwrap();
        let agent = sent[0]
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("user-agent:"))
            .expect("upstream request omitted the configured User-Agent");
        assert_eq!(
            agent.split_once(':').unwrap().1.trim(),
            crate::config::DEFAULT_USER_AGENT
        );
    }

    #[tokio::test]
    async fn transport_restricts_metadata_before_sending_to_the_proxy() {
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            false,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let mut input = request();
        input.headers.insert(
            "referer",
            "http://source.example/private?token=secret#fragment"
                .parse()
                .unwrap(),
        );
        input
            .headers
            .insert("origin", "http://source.example".parse().unwrap());
        http.get(1001, job.id, input, &CancellationToken::new())
            .await
            .unwrap();
        let sent = server.await.unwrap();
        assert!(sent[0].contains("referer: http://source.example/\r\n"));
        assert!(!sent[0].contains("private?token=secret"));
        assert!(sent[0].contains("origin: http://source.example\r\n"));

        let mut invalid = request();
        invalid.headers.insert(
            "origin",
            "http://source.example/private?token=secret"
                .parse()
                .unwrap(),
        );
        assert!(matches!(
            http.get(1001, job.id, invalid, &CancellationToken::new())
                .await,
            Err(ErrorCode::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn cache_validators_are_stripped_before_https_proxy() {
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            false,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let mut input = request();
        input
            .headers
            .insert("if-none-match", "\"session-tag\"".parse().unwrap());
        input.headers.insert(
            "if-modified-since",
            "Tue, 01 Jan 2030 00:00:00 GMT".parse().unwrap(),
        );
        http.get(1001, job.id, input, &CancellationToken::new())
            .await
            .unwrap();
        let sent = server.await.unwrap();
        assert!(!sent[0].contains("if-none-match:"));
        assert!(!sent[0].contains("if-modified-since:"));
    }

    #[test]
    fn transport_metadata_guard_covers_opaque_https_tunnels() {
        let mut secure = request();
        secure.target = PublicUrl::parse("https://target.example/page").unwrap();
        secure.headers.insert(
            REFERER,
            "https://source.example/private?token=secret"
                .parse()
                .unwrap(),
        );
        restrict_request_metadata(&mut secure).unwrap();
        assert_eq!(secure.headers[REFERER], "https://source.example/");

        let mut downgrade = request();
        downgrade.headers.insert(
            REFERER,
            "https://source.example/private?token=secret"
                .parse()
                .unwrap(),
        );
        restrict_request_metadata(&mut downgrade).unwrap();
        assert!(!downgrade.headers.contains_key(REFERER));

        let mut duplicate = request();
        duplicate
            .headers
            .append(REFERER, "http://source.example/one".parse().unwrap());
        duplicate
            .headers
            .append(REFERER, "http://source.example/two".parse().unwrap());
        assert!(matches!(
            restrict_request_metadata(&mut duplicate),
            Err(ErrorCode::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn small_job_reads_small_responses_without_reserving_the_operator_maximum() {
        let (_root, http, ledger, server) = fixture(
            2,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            false,
        )
        .await;
        let job = ledger
            .start(
                1001,
                RequestedLimits {
                    bytes: Some(2_000_000),
                    ..Default::default()
                },
            )
            .unwrap();
        for _ in 0..2 {
            let mut input = request();
            input.max_bytes = 32 * crate::config::MIB;
            assert_eq!(
                http.get(1001, job.id, input, &CancellationToken::new())
                    .await
                    .unwrap()
                    .body,
                b"ok"
            );
        }
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.used_bytes, 4);
        assert_eq!(server.await.unwrap().len(), 2);
    }

    fn browser_input(method: &str, body: &[u8]) -> crate::browser::wire::HttpRequest {
        use base64::Engine;
        crate::browser::wire::HttpRequest {
            url: "http://example.com/read".into(),
            method: method.into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body_base64: base64::engine::general_purpose::STANDARD.encode(body),
            resource_type: "Fetch".into(),
            main_document: false,
            redirects: 0,
        }
    }

    #[tokio::test]
    async fn local_search_is_a_separate_capability_not_a_url_override() {
        let (_root, http, ledger, public) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npublic",
            false,
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("searxng.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let local = tokio::spawn(async move {
            let mut stream = BufReader::new(listener.accept().await.unwrap().0);
            let mut first = String::new();
            stream.read_line(&mut first).await.unwrap();
            assert!(first.starts_with("GET /search?q=example HTTP/1.1"));
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            stream
                .get_mut()
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nlocal",
                )
                .await
                .unwrap();
        });
        let http = Arc::try_unwrap(http)
            .ok()
            .unwrap()
            .with_searxng_socket(Some(&socket))
            .unwrap();
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let make_request = || HttpRequest {
            target: PublicUrl::parse("http://searxng.invalid/search?q=example").unwrap(),
            query: true,
            ..request()
        };
        let stop = CancellationToken::new();
        assert_eq!(
            http.searxng(1001, job.id, make_request(), &stop)
                .await
                .unwrap()
                .body,
            b"local"
        );
        // Even the identical URL through ordinary retrieval still uses egress.
        assert_eq!(
            http.get(1001, job.id, make_request(), &stop)
                .await
                .unwrap()
                .body,
            b"public"
        );
        assert!(matches!(
            http.searxng(1001, job.id, request(), &stop).await,
            Err(ErrorCode::PolicyDenied)
        ));
        local.await.unwrap();
        public.await.unwrap();
    }

    #[tokio::test]
    async fn clamped_response_cannot_overrun_the_remaining_job_budget() {
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef",
            false,
        )
        .await;
        let job = ledger
            .start(
                1001,
                RequestedLimits {
                    bytes: Some(3),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(matches!(
            http.get(1001, job.id, request(), &CancellationToken::new())
                .await,
            Err(ErrorCode::SizeLimit)
        ));
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.used_bytes, 3);
        assert!(matches!(
            http.get(1001, job.id, request(), &CancellationToken::new())
                .await,
            Err(ErrorCode::BudgetExceeded)
        ));
        server.await.unwrap();
    }

    fn post_rules(body: &[u8]) -> Vec<crate::config::ReadPostRule> {
        vec![crate::config::ReadPostRule {
            origin: "http://example.com".into(),
            path: "/read".into(),
            max_bytes: 1024,
            operation: crate::config::ReadPostOperation::ExactBody {
                sha256: crate::policy::sha256(body),
                content_type: "application/json".into(),
            },
        }]
    }

    #[tokio::test]
    async fn reviewed_post_sends_exact_body_and_charges_both_directions() {
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            false,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let body = br#"{"query":"article"}"#;
        let rules = post_rules(body);
        let result = http
            .browser(
                1001,
                job.id,
                BrowserRequest {
                    request: browser_input("POST", body),
                    rules: &rules,
                    max_bytes: 64,
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.body, b"ok");
        let sent = server.await.unwrap();
        assert!(sent[0].starts_with("POST http://example.com/read HTTP/1.1\r\n"));
        assert!(sent[0].ends_with(std::str::from_utf8(body).unwrap()));
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!(usage.used_bytes, body.len() as u64 + 2);
        assert_eq!(usage.requests, 1);
        assert_eq!(usage.held_micro_usd, 0);
    }

    #[tokio::test]
    async fn reviewed_preflight_sends_a_real_credential_free_options_request() {
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: http://source.example\r\nAccess-Control-Allow-Methods: POST\r\nAccess-Control-Allow-Headers: content-type\r\nConnection: close\r\n\r\n",
            false,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let rules = post_rules(br#"{"query":"article"}"#);
        let mut input = browser_input("OPTIONS", b"");
        input.headers = vec![
            ("origin".into(), "http://source.example".into()),
            ("access-control-request-method".into(), "POST".into()),
            (
                "access-control-request-headers".into(),
                "content-type".into(),
            ),
            ("referer".into(), "http://source.example/private".into()),
        ];
        let response = http
            .browser(
                1001,
                job.id,
                BrowserRequest {
                    request: input,
                    rules: &rules,
                    max_bytes: 8192,
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 204);
        assert_eq!(
            response.headers["access-control-allow-origin"],
            "http://source.example"
        );
        let sent = server.await.unwrap();
        assert!(sent[0].starts_with("OPTIONS http://example.com/read HTTP/1.1\r\n"));
        assert!(sent[0].contains("access-control-request-method: POST\r\n"));
        assert!(sent[0].contains("access-control-request-headers: content-type\r\n"));
        assert!(!sent[0].to_ascii_lowercase().contains("referer:"));
        assert!(!sent[0].to_ascii_lowercase().contains("cookie:"));
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.requests, 1);
    }

    #[tokio::test]
    async fn head_preserves_headers_without_charging_declared_entity_bytes() {
        let (_root, http, ledger, server) = fixture(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 90000\r\nConnection: close\r\n\r\n",
            false,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let result = http
            .browser(
                1001,
                job.id,
                BrowserRequest {
                    request: browser_input("HEAD", b""),
                    rules: &[],
                    max_bytes: 64,
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(result.body.is_empty());
        assert_eq!(result.headers["content-length"], "90000");
        assert!(server.await.unwrap()[0].starts_with("HEAD http://example.com/read HTTP/1.1\r\n"));
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!(usage.used_bytes, 0);
        assert_eq!(usage.requests, 1);
    }

    #[tokio::test]
    async fn browser_policy_cancellation_and_body_budget_fail_before_network() {
        let (_root, http, ledger, server) = fixture(0, b"", false).await;
        let job = ledger
            .start(
                1001,
                RequestedLimits {
                    bytes: Some(3),
                    ..RequestedLimits::default()
                },
            )
            .unwrap();
        let rules = post_rules(b"{}");
        for (body, cancelled, expected) in [
            (b"[]".as_slice(), false, ErrorCode::PolicyDenied),
            (b"{}".as_slice(), true, ErrorCode::Cancelled),
            (b"{}".as_slice(), false, ErrorCode::BudgetExceeded),
        ] {
            let stop = CancellationToken::new();
            if cancelled {
                stop.cancel();
            }
            assert!(matches!(http.browser(1001, job.id, BrowserRequest {
                request: browser_input("POST", body), rules: &rules, max_bytes: 64,
            }, &stop).await, Err(error) if error == expected));
        }
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.requests, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn actual_parallel_requests_cross_the_explicit_unix_proxy() {
        let (_root, http, ledger, server) = fixture(
            2,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            true,
        )
        .await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let stop = CancellationToken::new();
        let (a, b) = tokio::join!(
            http.get(1001, job.id, request(), &stop),
            http.get(1001, job.id, request(), &stop)
        );
        assert_eq!(a.unwrap().body, b"ok");
        assert_eq!(b.unwrap().body, b"ok");
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|r| r.starts_with("GET http://example.com/?signed=a%2Fb&z=1 HTTP/1.1\r\n"))
        );
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.requests, 2);
    }

    #[tokio::test]
    async fn redirect_is_returned_without_following_private_target() {
        let (_root, http, ledger, server) = fixture(1, b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", false).await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let response = http
            .get(1001, job.id, request(), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(server.await.unwrap().len(), 1);
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.requests, 1);
    }

    #[tokio::test]
    async fn oversized_and_uncertain_provider_responses_keep_accounting() {
        let (_root, http, ledger, server) = fixture(1, b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789", false).await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let mut request = request();
        request.max_bytes = 4;
        request.micro_usd = 5000;
        request.query = true;
        assert!(matches!(
            http.get(1001, job.id, request, &CancellationToken::new())
                .await,
            Err(ErrorCode::SizeLimit)
        ));
        server.await.unwrap();
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!(usage.used_bytes, 5);
        assert_eq!(usage.held_micro_usd, 5000);
        assert_eq!(usage.known_micro_usd, 0);
    }

    #[tokio::test]
    async fn documented_unbilled_errors_release_money_even_if_body_is_oversized() {
        let (_root, http, ledger, server) = fixture(1, b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789", false).await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let mut request = request();
        request.max_bytes = 4;
        request.micro_usd = 5000;
        request.errors_are_unbilled = true;
        assert!(matches!(
            http.get(1001, job.id, request, &CancellationToken::new())
                .await,
            Err(ErrorCode::SizeLimit)
        ));
        server.await.unwrap();
        let usage = ledger.get(1001, job.id).unwrap().usage;
        assert_eq!(
            (
                usage.used_bytes,
                usage.known_micro_usd,
                usage.held_micro_usd
            ),
            (5, 0, 0)
        );
    }

    #[tokio::test]
    async fn cancelled_before_admission_never_spends() {
        let (_root, http, ledger, server) = fixture(0, b"", false).await;
        let job = ledger.start(1001, RequestedLimits::default()).unwrap();
        let stop = CancellationToken::new();
        stop.cancel();
        assert!(matches!(
            http.get(1001, job.id, request(), &stop).await,
            Err(ErrorCode::Cancelled)
        ));
        assert_eq!(ledger.get(1001, job.id).unwrap().usage.requests, 0);
        server.await.unwrap();
    }

    #[test]
    fn retry_after_never_shortens_a_long_server_delay() {
        assert_eq!(retry_after("120", Duration::from_secs(30)), None);
        assert_eq!(
            retry_after("2", Duration::from_secs(30)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(retry_after("-5", Duration::from_secs(30)), None);
    }

    #[test]
    fn repeated_retry_after_uses_the_longest_valid_delay() {
        let mut headers = HeaderMap::new();
        headers.append("retry-after", HeaderValue::from_static("0"));
        headers.append("retry-after", HeaderValue::from_static("30"));
        assert_eq!(
            retry_after_headers(&headers, Duration::from_secs(60)),
            Some(Duration::from_secs(30))
        );
        assert_eq!(retry_after_headers(&headers, Duration::from_secs(5)), None);
        headers.append("retry-after", HeaderValue::from_static("invalid"));
        assert_eq!(retry_after_headers(&headers, Duration::from_secs(60)), None);
    }
}
