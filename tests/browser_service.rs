//! Real service/socket/browser integration with synthetic HTTP and extraction.
//! The fixture never connects to a provider or a public network.
use base64::Engine;
use secure_research::{
    bridge::Bridge,
    browser::sandbox::SandboxConfig,
    budget::{Charge, JobState, Ledger},
    config::{Config, Privacy, ReadPostOperation, ReadPostRule},
    egress::{EgressMode, EgressState},
    error::{ErrorCode, Result},
    fetch::Parser,
    http::{BrowserRequest, HttpRequest, HttpResponse, Transport},
    policy::sha256,
    protocol::Tool,
    provider::Context,
    rpc,
    service::{Dependencies, Service},
    store::EvidenceStore,
    worker::{self, ExtractionInput, ParsedDocument, PdfInfo},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{net::UnixListener, sync::Notify};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn required(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .expect("missing pinned browser test setting")
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(90), cleanup_race())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(90), actions_and_sources())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(90), cors_read_post())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(90), fetch_modes_and_budgets())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(90), subrequest_budget())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(90), cancellation())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(90), mcp_browser())
                .await
                .unwrap();
        });
}

struct Upstream {
    ledger: Arc<Ledger>,
    entered: Notify,
    cancelled: Notify,
    release: Notify,
    browser_calls: Mutex<Vec<String>>,
    read_post_methods: Mutex<Vec<String>>,
    deny_preflight: AtomicBool,
}

#[async_trait::async_trait]
impl Transport for Upstream {
    async fn get(
        &self,
        owner: u32,
        job: Uuid,
        request: HttpRequest,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let charge = self.ledger.reserve(
            owner,
            job,
            Charge {
                requests: 1,
                bytes: request.max_bytes + 1,
                ..Default::default()
            },
        )?;
        let path = request.target.url().path();
        if matches!(path, "/held" | "/hang") {
            self.entered.notify_one();
            stop.cancelled().await;
            self.cancelled.notify_one();
            self.release.notified().await;
            // Model IO that finishes after cancellation. The broker must join
            // its ensuing archive write before strict evidence is deleted.
        }
        let streamed = if path == "/stream-auto" {
            let cards = (0..20)
                .map(|n| {
                    if n < 9 {
                        format!("<p>Kept card {n} é 👩‍🔬 Unicode quote.</p>")
                    } else {
                        format!("<p data-extra>Unfiltered surplus {n} é 👩‍🔬.</p>")
                    }
                })
                .collect::<String>();
            format!(
                r#"<!doctype html><head><link rel="icon" href="data:,"></head><main><template id="B:0"></template></main><div hidden id="S:0">{cards}</div><script>function $RC(boundary,payload) {{ const el=document.getElementById(payload);document.getElementById(boundary).replaceWith(el);el.removeAttribute('hidden');for(const extra of el.querySelectorAll('[data-extra]'))extra.remove(); }}$RC("B:0","S:0")</script>"#
            )
        } else {
            String::new()
        };
        let (status, body) = match path {
            "/stream-auto" => (200, streamed.as_str()),
            "/robots.txt" if request.target.url().host_str() == Some("warning.example.com") => {
                (503, "")
            }
            "/robots.txt" => (200, "User-agent: *\nDisallow: /robots-denied\n"),
            "/held" => (200, "late evidence"),
            "/image" => (
                200,
                "<!doctype html><p>Exact é 👩‍🔬 quote.</p><img src='/held'>",
            ),
            "/actions" => (
                200,
                "<!doctype html><p>Exact é 👩‍🔬 quote.</p><a href='/next'>Next</a><details><summary>More</summary>Expanded quote.</details><div style='height:2000px'>Long page.</div>",
            ),
            "/cors-page" => (
                200,
                "<!doctype html><p id='status'>pending</p><script>fetch('https://other.example.com/read', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{\"query\":\"article\"}'}).then(response => response.text()).then(text => document.getElementById('status').textContent = text).catch(() => document.getElementById('status').textContent = 'blocked');</script>",
            ),
            "/next" => (200, "<!doctype html><p>Next quote.</p>"),
            "/auto" | "/render-fail" | "/render-policy-denied" | "/parser-fail" => (
                200,
                "<!doctype html><head><link rel='icon' href='data:,'></head><p id='text'></p><script>document.querySelector('#text').textContent='Rendered é 👩‍🔬 quote.';</script>",
            ),
            "/denied" => (403, "<!doctype html><script>/* blocked */</script>"),
            "/private-redirect" => (302, ""),
            _ => (200, "<!doctype html><p>Exact é 👩‍🔬 quote.</p>"),
        };
        charge.finish(body.len() as u64, Some(0))?;
        let mut headers: http::HeaderMap = [(
            http::header::CONTENT_TYPE,
            "text/html; charset=utf-8".parse().unwrap(),
        )]
        .into_iter()
        .collect();
        if path == "/private-redirect" {
            headers.insert(
                http::header::LOCATION,
                "http://127.0.0.1/secret".parse().unwrap(),
            );
        }
        Ok(HttpResponse {
            status,
            headers,
            body: body.as_bytes().to_vec(),
        })
    }

    async fn browser(
        &self,
        owner: u32,
        job: Uuid,
        input: BrowserRequest<'_>,
        stop: &CancellationToken,
    ) -> Result<HttpResponse> {
        let checked = secure_research::browser::request::check(&input.request, input.rules)?;
        self.browser_calls
            .lock()
            .unwrap()
            .push(checked.target.as_str().to_owned());
        if checked.target.url().path() == "/read" {
            self.read_post_methods
                .lock()
                .unwrap()
                .push(checked.method.as_str().to_owned());
            let (status, body) = if checked.method == http::Method::OPTIONS {
                assert!(!checked.headers.contains_key("cookie"));
                assert!(!checked.headers.contains_key("referer"));
                assert_eq!(checked.headers["access-control-request-method"], "POST");
                assert!(input.max_bytes <= 8192);
                if self.deny_preflight.load(Ordering::SeqCst) {
                    (403, b"blocked".as_slice())
                } else {
                    (204, b"".as_slice())
                }
            } else {
                assert_eq!(checked.method, http::Method::POST);
                assert_eq!(checked.body, br#"{"query":"article"}"#);
                assert_eq!(checked.headers["referer"], "https://example.com/");
                (200, b"Read quote.".as_slice())
            };
            self.ledger
                .reserve(
                    owner,
                    job,
                    Charge {
                        requests: 1,
                        bytes: input.max_bytes + 1,
                        ..Default::default()
                    },
                )?
                .finish(body.len() as u64, Some(0))?;
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "access-control-allow-origin",
                "https://example.com".parse().unwrap(),
            );
            headers.insert("access-control-allow-methods", "POST".parse().unwrap());
            headers.insert(
                "access-control-allow-headers",
                "content-type".parse().unwrap(),
            );
            headers.insert("content-type", "text/plain".parse().unwrap());
            return Ok(HttpResponse {
                status,
                headers,
                body: body.to_vec(),
            });
        }
        if checked.target.url().path() == "/render-fail" {
            return Err(ErrorCode::AccessBlocked);
        }
        if checked.target.url().path() == "/render-policy-denied" {
            // Synthetic broker denial isolates the auto-result merge path.
            return Err(ErrorCode::BrowserRequestDenied);
        }
        self.get(
            owner,
            job,
            HttpRequest {
                target: checked.target,
                headers: checked.headers,
                max_bytes: input.max_bytes,
                micro_usd: 0,
                errors_are_unbilled: false,
                query: false,
            },
            stop,
        )
        .await
    }
}

struct FixtureParser;
#[async_trait::async_trait]
impl Parser for FixtureParser {
    async fn inspect(&self, _: &Context, _: ExtractionInput<'_>) -> Result<PdfInfo> {
        Err(ErrorCode::ExtractionFailed)
    }
    async fn extract(&self, _: &Context, input: ExtractionInput<'_>) -> Result<ParsedDocument> {
        if input.base.url().path() == "/parser-fail" {
            return Err(ErrorCode::ExtractionFailed);
        }
        worker::parse_html(input.bytes, input.base, input.content_type)
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    temporary: PathBuf,
    service: Arc<Service>,
    store: Arc<EvidenceStore>,
    upstream: Arc<Upstream>,
    owner: u32,
    heartbeat: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.heartbeat.abort();
    }
}
impl Fixture {
    async fn new(idle_seconds: u64) -> Self {
        Self::with_read_post_rules(idle_seconds, vec![]).await
    }

    async fn with_read_post_rules(idle_seconds: u64, rules: Vec<ReadPostRule>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let owner = rustix::process::getuid().as_raw();
        let mut config = Config {
            privacy: Privacy::Strict,
            state_directory: root.path().join("state"),
            egress_uid: Some(1002),
            allowed_client_uids: vec![owner, owner + 1],
            ..Default::default()
        };
        config.limits.retries = 0;
        config.limits.browser_seconds = 5;
        config.browser.enable = true;
        config.browser.idle_seconds = idle_seconds;
        config.browser.read_post_rules = rules;
        config.browser.executable = required("RESEARCH_TEST_CHROMIUM");
        config.browser.sandbox = Some(SandboxConfig {
            worker: PathBuf::from(env!("CARGO_BIN_EXE_research-browser-worker")),
            bubblewrap: required("RESEARCH_TEST_BWRAP"),
            chromium_sandbox: required("RESEARCH_TEST_CHROMIUM_SANDBOX"),
            fontconfig: required("RESEARCH_TEST_FONTCONFIG"),
            store_paths: std::fs::read_to_string(required("RESEARCH_TEST_CHROMIUM_CLOSURE"))
                .unwrap()
                .lines()
                .map(PathBuf::from)
                .collect(),
        });
        std::fs::create_dir(&config.state_directory).unwrap();
        let temporary = root.path().join("temporary");
        std::fs::create_dir(&temporary).unwrap();
        let ledger = Ledger::open(
            &config.state_directory.join("budget.sqlite"),
            config.limits.clone(),
        )
        .unwrap();
        let store = EvidenceStore::open(&config, temporary.clone()).unwrap();
        let upstream = Arc::new(Upstream {
            ledger: ledger.clone(),
            entered: Notify::new(),
            cancelled: Notify::new(),
            release: Notify::new(),
            browser_calls: Mutex::new(vec![]),
            read_post_methods: Mutex::new(vec![]),
            deny_preflight: AtomicBool::new(false),
        });
        let service = Service::new(
            config,
            Dependencies {
                ledger,
                store: store.clone(),
                http: upstream.clone(),
                parser: Some(Arc::new(FixtureParser)),
                search_providers: vec![],
                scrape_providers: vec![],
                summarize_providers: vec![],
            },
        )
        .unwrap();
        let ready = EgressState {
            version: 1,
            generation: Uuid::new_v4(),
            mode: EgressMode::Ready,
            valid_until: chrono::Utc::now().timestamp() + 10,
            region: None,
        };
        service.update_egress(ready.clone()).await.unwrap();
        let heartbeat = tokio::spawn({
            let service = service.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let mut refreshed = ready.clone();
                    refreshed.valid_until = chrono::Utc::now().timestamp() + 10;
                    service.update_egress(refreshed).await.unwrap();
                }
            }
        });
        Self {
            _root: root,
            temporary,
            service,
            store,
            upstream,
            owner,
            heartbeat,
        }
    }

    async fn connect(&self) -> (Arc<Bridge>, tokio::task::JoinHandle<Result<()>>) {
        let socket = self._root.path().join(Uuid::new_v4().to_string());
        let listener = UnixListener::bind(&socket).unwrap();
        let service = self.service.clone();
        let serving = tokio::spawn(async move {
            rpc::connection(
                listener.accept().await.unwrap().0,
                service,
                CancellationToken::new(),
            )
            .await
        });
        (Arc::new(Bridge::connect(&socket).await.unwrap()), serving)
    }
}

async fn call(bridge: &Bridge, tool: Tool, args: Value) -> Value {
    bridge
        .call(tool, args, CancellationToken::new())
        .await
        .unwrap()
}
async fn job(bridge: &Bridge) -> Uuid {
    serde_json::from_value(
        call(bridge, Tool::ResearchJob, json!({"operation":"start"})).await["job"]["id"].clone(),
    )
    .unwrap()
}

async fn cors_read_post() {
    let body = br#"{"query":"article"}"#;
    let rules = vec![ReadPostRule {
        origin: "https://other.example.com".into(),
        path: "/read".into(),
        max_bytes: 128,
        operation: ReadPostOperation::ExactBody {
            sha256: sha256(body),
            content_type: "application/json".into(),
        },
    }];
    for denied in [false, true] {
        let fixture = Fixture::with_read_post_rules(30, rules.clone()).await;
        fixture
            .upstream
            .deny_preflight
            .store(denied, Ordering::SeqCst);
        let (bridge, serving) = fixture.connect().await;
        let id = job(&bridge).await;
        let opened = call(
            &bridge,
            Tool::ResearchBrowser,
            json!({"action":"open","job_id":id,"url":"https://example.com/cors-page"}),
        )
        .await;
        let session = opened["session_id"].clone();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let read = call(
            &bridge,
            Tool::ResearchBrowser,
            json!({"action":"read","job_id":id,"session_id":session}),
        )
        .await;
        let expected_text = if denied { "blocked" } else { "Read quote." };
        assert!(
            source_text(&bridge, &read["source"])
                .await
                .contains(expected_text),
            "{read}"
        );
        if denied {
            assert_eq!(read["partial"], true, "{read}");
            assert!(
                read["page"]["request_errors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|error| error == "access_blocked"),
                "{read}"
            );
        }
        let methods = fixture.upstream.read_post_methods.lock().unwrap().clone();
        assert_eq!(
            methods.as_slice(),
            if denied {
                &["OPTIONS"][..]
            } else {
                &["OPTIONS", "POST"][..]
            }
        );
        let status = call(
            &bridge,
            Tool::ResearchJob,
            json!({"operation":"status","job_id":id}),
        )
        .await;
        assert!(status["job"]["usage"]["requests"].as_u64().unwrap() >= 2);
        assert_eq!(status["job"]["usage"]["known_micro_usd"], 0);
        let closed = call(
            &bridge,
            Tool::ResearchBrowser,
            json!({"action":"close","job_id":id,"session_id":session}),
        )
        .await;
        assert_eq!(closed["closed"], true);
        bridge.close().await;
        serving.await.unwrap().unwrap();
    }
}

async fn cleanup_race() {
    let fixture = Fixture::new(1).await;
    let (bridge, serving) = fixture.connect().await;
    let id = job(&bridge).await;
    let opened = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"open","job_id":id,"url":"https://example.com/image"}),
    )
    .await;
    assert_eq!(opened["closed"], false);
    assert_eq!(opened["partial"], true);
    assert_eq!(opened["page"]["pending_requests"], true);
    fixture.upstream.entered.notified().await;
    // Idle expiry starts cleanup while no service operation is active.
    fixture.upstream.cancelled.notified().await;
    let maintenance = fixture.service.maintenance();
    tokio::pin!(maintenance);
    assert!(futures_util::poll!(maintenance.as_mut()).is_pending());
    let closing = fixture
        .service
        .close_job(fixture.owner, id, JobState::Cancelled);
    tokio::pin!(closing);
    assert!(
        futures_util::poll!(closing.as_mut()).is_pending(),
        "job close skipped a browser still draining in maintenance"
    );
    assert!(
        !fixture
            .store
            .job_sources(fixture.owner, id)
            .await
            .unwrap()
            .is_empty(),
        "strict evidence disappeared before broker work drained"
    );
    fixture.upstream.release.notify_one();
    closing.await.unwrap();
    maintenance.await.unwrap();
    assert!(
        fixture
            .store
            .job_sources(fixture.owner, id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_dir(&fixture.temporary).unwrap().count(),
        0,
        "browser workspace or strict evidence survived cleanup"
    );
    bridge.close().await;
    serving.await.unwrap().unwrap();
}

fn reference(page: &Value, kind: &str) -> String {
    page["page"]["references"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == kind)
        .unwrap()["reference"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn source_text(bridge: &Bridge, source: &Value) -> String {
    call(bridge, Tool::ResearchRead, json!({"kind":"source","source_id":source["id"],"representation_id":source["primary_representation"]["id"]})).await["content"].as_str().unwrap().to_owned()
}

async fn actions_and_sources() {
    let fixture = Fixture::new(30).await;
    let (bridge, serving) = fixture.connect().await;
    let id = job(&bridge).await;
    let other = job(&bridge).await;
    let opened = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"open","job_id":id,"url":"https://example.com/actions"}),
    )
    .await;
    let session = opened["session_id"].clone();
    let expand = reference(&opened, "expand");
    assert!(
        source_text(&bridge, &opened["source"])
            .await
            .contains("Exact é 👩‍🔬 quote.")
    );
    let dom = call(
        &bridge,
        Tool::ResearchRead,
        json!({"kind":"metadata","source_id":opened["dom_source_id"]}),
    )
    .await;
    assert_eq!(dom["representations"][0]["kind"], "rendered_dom");
    assert_ne!(dom["id"], opened["source"]["id"]);
    let raw = &opened["session_http_entities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entity| entity["main_document"] == true)
        .unwrap()["source"];
    assert_ne!(raw["id"], dom["id"]);
    let raw_text = call(&bridge, Tool::ResearchRead, json!({"kind":"source","source_id":raw["id"],"representation_id":raw["representations"][0]["id"]})).await;
    let raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_text["content"].as_str().unwrap())
        .unwrap();
    assert!(
        String::from_utf8(raw_bytes)
            .unwrap()
            .contains("Exact é 👩‍🔬 quote.")
    );
    assert_eq!(
        bridge
            .call(
                Tool::ResearchBrowser,
                json!({"action":"read","job_id":other,"session_id":session}),
                CancellationToken::new()
            )
            .await,
        Err(ErrorCode::NotFound)
    );
    let foreign = fixture
        .service
        .call(
            fixture.owner + 1,
            Uuid::new_v4(),
            Tool::ResearchJob,
            json!({"operation":"start"}),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .service
            .call(
                fixture.owner + 1,
                Uuid::new_v4(),
                Tool::ResearchBrowser,
                json!({"action":"read","job_id":foreign["job"]["id"],"session_id":session}),
                CancellationToken::new()
            )
            .await,
        Err(ErrorCode::NotFound)
    );
    let expanded = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"expand","job_id":id,"session_id":session,"reference":expand}),
    )
    .await;
    let dom = call(
        &bridge,
        Tool::ResearchRead,
        json!({"kind":"metadata","source_id":expanded["dom_source_id"]}),
    )
    .await;
    let content = call(&bridge, Tool::ResearchRead, json!({"kind":"source","source_id":dom["id"],"representation_id":dom["representations"][0]["id"]})).await;
    assert!(
        content["content"]
            .as_str()
            .unwrap()
            .contains("<details open=")
    );
    let scrolled = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"scroll","job_id":id,"session_id":session,"direction":"down"}),
    )
    .await;
    let followed = call(&bridge, Tool::ResearchBrowser, json!({"action":"follow_link","job_id":id,"session_id":session,"reference":reference(&scrolled,"link")})).await;
    assert_eq!(
        followed["source"]["original_url"],
        "https://example.com/next"
    );
    assert_eq!(
        bridge
            .call(
                Tool::ResearchBrowser,
                json!({"action":"expand","job_id":id,"session_id":session,"reference":expand}),
                CancellationToken::new()
            )
            .await,
        Err(ErrorCode::StaleReference)
    );
    let read = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"read","job_id":id,"session_id":session}),
    )
    .await;
    assert!(
        source_text(&bridge, &read["source"])
            .await
            .contains("Next quote.")
    );
    let closed = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"close","job_id":id,"session_id":session}),
    )
    .await;
    assert_eq!(closed["closed"], true);
    assert_eq!(
        bridge
            .call(
                Tool::ResearchBrowser,
                json!({"action":"read","job_id":id,"session_id":session}),
                CancellationToken::new()
            )
            .await,
        Err(ErrorCode::NotFound)
    );
    fixture.service.shutdown().await.unwrap();
    assert_eq!(std::fs::read_dir(&fixture.temporary).unwrap().count(), 0);
    bridge.close().await;
    serving.await.unwrap().unwrap();
}

async fn fetch_modes_and_budgets() {
    let fixture = Fixture::new(30).await;
    let (bridge, serving) = fixture.connect().await;
    let id = job(&bridge).await;
    // More unique URLs than browser slots must complete without capacity loss.
    let urls: Vec<_> = (0..4)
        .map(|n| format!("https://example.com/auto?n={n}"))
        .chain(std::iter::once("https://example.com/auto?n=0#quote".into()))
        .collect();
    let fetched = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"mode":"browser","urls":urls}),
    )
    .await;
    assert_eq!(fetched["coverage"]["success"], 5, "{fetched}");
    assert_eq!(fetched["items"][4]["duplicate_of"], 0);
    assert_eq!(fetched["usage"]["browser_actions"], 4);
    for item in fetched["items"].as_array().unwrap() {
        assert_eq!(item["data"]["closed"], true);
        assert!(
            source_text(&bridge, &item["data"]["source"])
                .await
                .contains("Rendered é 👩‍🔬 quote.")
        );
        assert_eq!(
            bridge
                .call(
                    Tool::ResearchBrowser,
                    json!({"action":"read","job_id":id,"session_id":item["data"]["session_id"]}),
                    CancellationToken::new()
                )
                .await,
            Err(ErrorCode::NotFound)
        );
    }
    let auto = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"urls":["https://example.com/auto"]}),
    )
    .await;
    let data = &auto["items"][0]["data"];
    assert_eq!(auto["coverage"]["success"], 1, "{auto}");
    assert_eq!(data["closed"], true);
    assert_eq!(data["http"]["javascript_required"], true);
    assert_eq!(data["javascript_required"], false);
    assert_ne!(data["http"]["source"]["id"], data["source"]["id"]);
    assert!(
        source_text(&bridge, &data["source"])
            .await
            .contains("Rendered é 👩‍🔬 quote.")
    );
    let before_http = fixture.upstream.browser_calls.lock().unwrap().len();
    let http = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"mode":"http","urls":["https://example.com/auto"]}),
    )
    .await;
    assert_eq!(http["items"][0]["data"]["javascript_required"], true);
    let streamed_http = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"mode":"http","urls":["https://example.com/stream-auto"]}),
    )
    .await;
    assert_eq!(streamed_http["coverage"]["partial"], 1);
    assert_eq!(
        streamed_http["items"][0]["data"]["javascript_required"],
        true
    );
    let static_text = source_text(&bridge, &streamed_http["items"][0]["data"]["source"]).await;
    assert_eq!(static_text.matches("Kept card").count(), 9);
    assert_eq!(static_text.matches("Unfiltered surplus").count(), 11);
    assert_eq!(
        fixture.upstream.browser_calls.lock().unwrap().len(),
        before_http,
        "HTTP mode invoked browser rendering"
    );
    let streamed_auto = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"mode":"auto","urls":["https://example.com/stream-auto"]}),
    )
    .await;
    assert_eq!(streamed_auto["coverage"]["success"], 1, "{streamed_auto}");
    let filtered = source_text(&bridge, &streamed_auto["items"][0]["data"]["source"]).await;
    assert_eq!(filtered.matches("Kept card").count(), 9);
    assert!(!filtered.contains("Unfiltered surplus"));
    let before_failures = fixture.upstream.browser_calls.lock().unwrap().len();
    let failures = call(&bridge, Tool::ResearchFetch, json!({"job_id":id,"urls":["https://example.com/denied","https://example.com/private-redirect","https://example.com/robots-denied","https://example.com/parser-fail"]})).await;
    for (index, error) in [
        "access_blocked",
        "destination_denied",
        "policy_denied",
        "extraction_failed",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(failures["items"][index]["error"], *error, "{failures}");
    }
    assert_eq!(
        fixture.upstream.browser_calls.lock().unwrap().len(),
        before_failures,
        "HTTP failures invoked browser fallback"
    );
    let failed_render = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"urls":["https://example.com/render-fail"]}),
    )
    .await;
    assert_eq!(failed_render["items"][0]["state"], "partial");
    assert_eq!(failed_render["items"][0]["error"], "access_blocked");
    let retained = &failed_render["items"][0]["data"];
    assert_eq!(retained["render_error"], "access_blocked");
    call(
        &bridge,
        Tool::ResearchRead,
        json!({"kind":"metadata","source_id":retained["raw_source_id"]}),
    )
    .await;
    let denied_render = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"urls":["https://example.com/render-policy-denied"]}),
    )
    .await;
    assert_eq!(denied_render["coverage"]["partial"], 1, "{denied_render}");
    assert_eq!(denied_render["items"][0]["error"], "policy_denied");
    let retained = &denied_render["items"][0]["data"];
    assert_eq!(retained["render_error"], "policy_denied");
    assert_eq!(
        retained["render_error_details"]["reason"],
        "browser_request_not_granted"
    );
    assert!(retained["source"]["id"].is_string());
    assert!(retained["http"].is_null());
    call(
        &bridge,
        Tool::ResearchRead,
        json!({"kind":"metadata","source_id":retained["raw_source_id"]}),
    )
    .await;
    call(
        &bridge,
        Tool::ResearchJob,
        json!({"operation":"finish","job_id":id}),
    )
    .await;

    for (limits, expected_actions) in [
        (json!({"browser_actions":0}), 0),
        (json!({"documents":0}), 1),
        (json!({"bytes":1}), 1),
    ] {
        let started = call(
            &bridge,
            Tool::ResearchJob,
            json!({"operation":"start","limits":limits}),
        )
        .await;
        let id = started["job"]["id"].clone();
        let denied = call(
            &bridge,
            Tool::ResearchFetch,
            json!({"job_id":id,"mode":"browser","urls":["https://example.com/auto"]}),
        )
        .await;
        assert_eq!(denied["items"][0]["error"], "budget_exceeded", "{denied}");
        assert_eq!(denied["usage"]["browser_actions"], expected_actions);
        call(
            &bridge,
            Tool::ResearchJob,
            json!({"operation":"finish","job_id":id}),
        )
        .await;
    }
    let id = job(&bridge).await;
    for (url, error) in [
        ("http://127.0.0.1/secret", "destination_denied"),
        ("https://example.com/private-redirect", "destination_denied"),
        ("https://example.com/robots-denied", "policy_denied"),
    ] {
        let denied = call(
            &bridge,
            Tool::ResearchFetch,
            json!({"job_id":id,"mode":"browser","urls":[url]}),
        )
        .await;
        assert_eq!(denied["items"][0]["error"], error, "{denied}");
        if url.ends_with("/robots-denied") {
            assert_eq!(
                denied["items"][0]["data"]["error_details"]["reason"],
                "robots_disallowed"
            );
        }
    }
    let denied = bridge
        .call_detailed(
            Tool::ResearchBrowser,
            json!({"action":"open","job_id":id,"url":"https://example.com/robots-denied"}),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::PolicyDenied);
    assert_eq!(
        serde_json::to_value(denied.details).unwrap()["reason"],
        "robots_disallowed"
    );
    let partial = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"mode":"browser","urls":["https://example.com/parser-fail"]}),
    )
    .await;
    assert_eq!(partial["items"][0]["state"], "partial");
    assert_eq!(partial["items"][0]["data"]["closed"], true);
    assert_eq!(
        partial["items"][0]["data"]["source"]["primary_representation"]["kind"],
        "rendered_dom"
    );
    let warning = call(
        &bridge,
        Tool::ResearchFetch,
        json!({"job_id":id,"mode":"browser","urls":["https://warning.example.com/auto"]}),
    )
    .await;
    assert_eq!(warning["coverage"]["success"], 1, "{warning}");
    assert!(
        warning["items"][0]["data"]["session_http_entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["source"]["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|warning| warning == "robots_unavailable"))
    );
    bridge.close().await;
    serving.await.unwrap().unwrap();
    let remaining: Vec<_> = std::fs::read_dir(&fixture.temporary)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        remaining.is_empty(),
        "temporary entries survived close: {remaining:?}"
    );
}

async fn subrequest_budget() {
    let fixture = Fixture::new(30).await;
    let (bridge, serving) = fixture.connect().await;
    let started = call(
        &bridge,
        Tool::ResearchJob,
        json!({"operation":"start","limits":{"requests":2}}),
    )
    .await;
    let id = started["job"]["id"].clone();
    // Robots and the main page consume the two available HTTP requests. The
    // image must be refused even though Chromium starts it as a subrequest.
    let opened = call(
        &bridge,
        Tool::ResearchBrowser,
        json!({"action":"open","job_id":id,"url":"https://example.com/image"}),
    )
    .await;
    assert_eq!(opened["closed"], false, "{opened}");
    assert!(
        opened["page"]["request_errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error == "budget_exceeded"),
        "{opened}"
    );
    let status = call(
        &bridge,
        Tool::ResearchJob,
        json!({"operation":"status","job_id":id}),
    )
    .await;
    assert_eq!(status["job"]["usage"]["requests"], 2);
    assert!(
        fixture
            .upstream
            .browser_calls
            .lock()
            .unwrap()
            .iter()
            .any(|url| url.ends_with("/held")),
        "Chromium did not attempt the budget-limited subrequest"
    );
    bridge.close().await;
    serving.await.unwrap().unwrap();
}

async fn cancellation() {
    for scenario in ["call", "job", "egress", "disconnect"] {
        let fixture = Fixture::new(30).await;
        let (bridge, serving) = fixture.connect().await;
        let id = job(&bridge).await;
        let stop = CancellationToken::new();
        let opening = tokio::spawn({
            let bridge = bridge.clone();
            let stop = stop.clone();
            async move {
                bridge
                    .call(
                        Tool::ResearchBrowser,
                        json!({"action":"open","job_id":id,"url":"https://example.com/hang"}),
                        stop,
                    )
                    .await
            }
        });
        fixture.upstream.entered.notified().await;
        if scenario == "egress" {
            fixture.heartbeat.abort();
        }
        if scenario == "call" {
            stop.cancel();
            fixture.upstream.cancelled.notified().await;
        }
        let cleanup = tokio::spawn({
            let service = fixture.service.clone();
            let bridge = bridge.clone();
            let owner = fixture.owner;
            async move {
                match scenario {
                    "egress" => service.update_egress(EgressState::offline()).await,
                    "disconnect" => {
                        bridge.close().await;
                        Ok(())
                    }
                    _ => service
                        .close_job(owner, id, JobState::Cancelled)
                        .await
                        .map(|_| ()),
                }
            }
        });
        if scenario != "call" {
            fixture.upstream.cancelled.notified().await;
        }
        if scenario != "disconnect" {
            assert!(
                !cleanup.is_finished(),
                "{scenario}: cleanup returned before broker IO finished"
            );
        }
        assert!(
            !serving.is_finished(),
            "connection cleanup returned before broker IO finished"
        );
        fixture.upstream.release.notify_one();
        cleanup.await.unwrap().unwrap();
        let result = opening.await.unwrap();
        assert_eq!(
            result,
            Err(if scenario == "egress" {
                ErrorCode::EgressChanged
            } else {
                ErrorCode::Cancelled
            }),
            "{scenario}"
        );
        bridge.close().await;
        serving.await.unwrap().unwrap();
        assert_eq!(
            std::fs::read_dir(&fixture.temporary).unwrap().count(),
            0,
            "{scenario}: leaked workspace/evidence"
        );
        assert!(
            fixture
                .store
                .job_sources(fixture.owner, id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

async fn mcp_exchange(
    input: &mut tokio::process::ChildStdin,
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    use tokio::io::AsyncWriteExt;
    let request = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
    input
        .write_all(format!("{request}\n").as_bytes())
        .await
        .unwrap();
    input.flush().await.unwrap();
    let reply: Value = serde_json::from_str(
        &lines
            .next_line()
            .await
            .unwrap()
            .expect("MCP closed before response"),
    )
    .unwrap();
    assert_eq!(reply["id"], id);
    assert!(reply.get("error").is_none(), "{reply}");
    assert_ne!(reply["result"]["isError"], true, "{reply}");
    reply["result"].clone()
}

async fn mcp_browser() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let fixture = Fixture::new(30).await;
    let socket = fixture._root.path().join("mcp.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let service = fixture.service.clone();
    let serving = tokio::spawn(async move {
        rpc::connection(
            listener.accept().await.unwrap().0,
            service,
            CancellationToken::new(),
        )
        .await
    });
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_research-client"))
        .arg("--socket")
        .arg(&socket)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    mcp_exchange(&mut input, &mut lines, 1, "initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"browser-fixture","version":"1"}})).await;
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    let started = mcp_exchange(
        &mut input,
        &mut lines,
        2,
        "tools/call",
        json!({"name":"research_job","arguments":{"operation":"start"}}),
    )
    .await;
    let id = started["structuredContent"]["job"]["id"].clone();
    let opened = mcp_exchange(&mut input, &mut lines, 3, "tools/call", json!({"name":"research_browser","arguments":{"action":"open","job_id":id,"url":"https://example.com/auto"}})).await;
    let source = &opened["structuredContent"]["source"];
    let read = mcp_exchange(&mut input, &mut lines, 4, "tools/call", json!({"name":"research_read","arguments":{"kind":"source","source_id":source["id"],"representation_id":source["primary_representation"]["id"]}})).await;
    assert!(
        read["structuredContent"]["content"]
            .as_str()
            .unwrap()
            .contains("Rendered é 👩‍🔬 quote.")
    );
    // Stdio EOF must close the still-open reading session and its job.
    drop(input);
    assert!(child.wait().await.unwrap().success());
    assert!(lines.next_line().await.unwrap().is_none());
    let mut diagnostics = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut diagnostics)
        .await
        .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics}");
    serving.await.unwrap().unwrap();
    assert_eq!(std::fs::read_dir(&fixture.temporary).unwrap().count(), 0);
}
