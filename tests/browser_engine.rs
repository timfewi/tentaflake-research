//! Actual private worker binary, pipes, body files and Chromium. The parent
//! supplies synthetic public responses; no real provider or host data is used.
use secure_research::{
    browser::{
        body::Bodies,
        engine::WorkerSettings,
        launch::Settings,
        request,
        sandbox::{SandboxConfig, Workspace},
        wire,
    },
    config::{MIB, ReadPostOperation, ReadPostRule},
    error::ErrorCode,
    policy::sha256,
    protocol::{read_frame, write_frame},
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::{ChildStdin, ChildStdout};

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
        .block_on(check());
}

async fn check() {
    let config = SandboxConfig {
        worker: PathBuf::from(env!("CARGO_BIN_EXE_research-browser-worker")),
        bubblewrap: required("RESEARCH_TEST_BWRAP"),
        chromium_sandbox: required("RESEARCH_TEST_CHROMIUM_SANDBOX"),
        fontconfig: required("RESEARCH_TEST_FONTCONFIG"),
        store_paths: std::fs::read_to_string(required("RESEARCH_TEST_CHROMIUM_CLOSURE"))
            .unwrap()
            .lines()
            .map(PathBuf::from)
            .collect(),
    };
    let settings = WorkerSettings {
        launch: Settings {
            chromium: required("RESEARCH_TEST_CHROMIUM"),
            width: 1365,
            height: 768,
            operation_seconds: 5,
            html_bytes: 8 * MIB,
            requests: 64,
            actions: 16,
            locale: "en-US".into(),
            timezone: "UTC".into(),
            accept_language: "en-US,en;q=0.9".into(),
        },
        read_post_rules: vec![],
        redirects: 5,
        response_bytes: 8 * MIB,
        idle_seconds: 10,
        lifetime_seconds: 30,
    };
    let root = tempfile::tempdir().unwrap();
    for scenario in [
        "normal",
        "referrer",
        "preflight",
        "adversarial",
        "disconnect",
        "timeout",
        "cancel_request",
    ] {
        let mut settings = settings.clone();
        if scenario == "preflight" {
            settings.read_post_rules = vec![ReadPostRule {
                origin: "https://other.example".into(),
                path: "/read".into(),
                max_bytes: 128,
                operation: ReadPostOperation::ExactBody {
                    sha256: sha256(br#"{"query":"article"}"#),
                    content_type: "application/json".into(),
                },
            }];
        }
        let workspace = Workspace::new(root.path()).unwrap();
        let workspace_path = workspace.root().to_owned();
        std::fs::write(
            workspace.root().join("responses/config.json"),
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        let mut command = workspace.command(&config, None).unwrap();
        command.args(["--", "/worker"]);
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let test = async {
            let mut fixture = Fixture::new(
                input,
                output,
                workspace.root(),
                settings.read_post_rules.clone(),
            );
            fixture.hang = scenario == "timeout";
            assert!(matches!(
                read_frame::<_, wire::Output>(&mut fixture.output)
                    .await
                    .unwrap(),
                Some(wire::Output::Ready { version: 1 })
            ));
            fixture
                .action(
                    1,
                    wire::Action::Open {
                        url: if scenario == "adversarial" {
                            "https://example.com/adversarial-sw"
                        } else if scenario == "referrer" {
                            "https://example.com/referrer-page?private=secret"
                        } else if scenario == "preflight" {
                            "https://example.com/preflight-page"
                        } else {
                            "https://example.com/engine"
                        }
                        .into(),
                    },
                )
                .await;
            if scenario == "disconnect" {
                // Stop while a navigation is waiting for its first HTTP entity.
                assert!(matches!(
                    read_frame::<_, wire::Output>(&mut fixture.output)
                        .await
                        .unwrap(),
                    Some(wire::Output::Http { .. })
                ));
                drop(fixture.input);
                let status = child.wait().await.unwrap();
                assert!(!status.success(), "disconnect unexpectedly completed a job");
                return;
            }
            if scenario == "timeout" {
                assert!(matches!(
                    fixture.completed(1).await,
                    Err(ErrorCode::Timeout)
                ));
                assert!(!child.wait().await.unwrap().success());
                return;
            }
            let first = fixture.completed(1).await.unwrap();
            if scenario == "referrer" {
                fixture.html(1, &first);
                assert!(
                    fixture.seen.contains("https://other.example/pixel"),
                    "cross-origin image did not reach the broker"
                );
                fixture.action(2, wire::Action::Close).await;
                loop {
                    match fixture.message().await {
                        wire::Output::Completed {
                            id: 2,
                            result: Ok(None),
                        } => break,
                        message => fixture.broker(message).await,
                    }
                }
                assert!(child.wait().await.unwrap().success());
                return;
            }
            if scenario == "preflight" {
                fixture.html(1, &first);
                tokio::time::sleep(Duration::from_secs(2)).await;
                fixture.action(2, wire::Action::Read).await;
                let read = fixture.completed(2).await.unwrap();
                let html = fixture.html(2, &read);
                assert!(
                    html.contains(">Read quote.</p>"),
                    "html={html} probes={:?} seen={:?} errors={:?}",
                    fixture.post_probes,
                    fixture.seen,
                    read.request_errors
                );
                assert_eq!(
                    fixture.post_probes,
                    vec!["OPTIONS".to_owned(), "POST".to_owned()]
                );
                fixture.action(3, wire::Action::Close).await;
                loop {
                    match fixture.message().await {
                        wire::Output::Completed {
                            id: 3,
                            result: Ok(None),
                        } => break,
                        message => fixture.broker(message).await,
                    }
                }
                assert!(child.wait().await.unwrap().success());
                return;
            }
            if scenario == "adversarial" {
                fixture.html(1, &first);
                tokio::time::sleep(Duration::from_millis(300)).await;
                fixture.action(2, wire::Action::Read).await;
                let service_worker = fixture.completed(2).await.unwrap();
                let service_worker_html = fixture.html(2, &service_worker);
                assert!(
                    service_worker_html.contains(">pending</p>"),
                    "service-worker registration unexpectedly completed: {service_worker_html}"
                );
                assert!(!fixture.seen.contains("https://example.com/sw.js"));
                fixture
                    .action(
                        3,
                        wire::Action::Open {
                            url: "https://example.com/adversarial-worker".into(),
                        },
                    )
                    .await;
                let worker_open = fixture.completed(3).await.unwrap();
                fixture.html(3, &worker_open);
                fixture.action(4, wire::Action::Read).await;
                let worker = fixture.completed(4).await.unwrap();
                fixture.html(4, &worker);
                assert!(
                    worker
                        .request_errors
                        .iter()
                        .filter(|error| **error == ErrorCode::PolicyDenied)
                        .count()
                        >= 1,
                    "dedicated worker target was not blocked"
                );
                assert!(
                    fixture.seen.contains("https://example.com/worker.js"),
                    "dedicated-worker script bypassed the intercepted transport"
                );
                fixture
                    .action(
                        5,
                        wire::Action::Open {
                            url: "https://example.com/adversarial-popup".into(),
                        },
                    )
                    .await;
                let popup_open = fixture.completed(5).await.unwrap();
                fixture.html(5, &popup_open);
                fixture.action(6, wire::Action::Read).await;
                let popup = fixture.completed(6).await.unwrap();
                fixture.html(6, &popup);
                assert!(
                    popup
                        .request_errors
                        .iter()
                        .filter(|error| **error == ErrorCode::PolicyDenied)
                        .count()
                        >= 1,
                    "blocked child-target policy error disappeared"
                );
                assert!(!fixture.seen.contains("https://example.com/popup"));
                fixture
                    .action(
                        7,
                        wire::Action::Open {
                            url: "https://example.com/adversarial".into(),
                        },
                    )
                    .await;
                let page = fixture.completed(7).await.unwrap();
                let html = fixture.html(7, &page);
                assert!(html.contains("Adversarial page"));
                assert!(
                    page.references
                        .iter()
                        .all(|reference| reference.label != "Download"),
                    "download link became an actionable reference"
                );
                assert!(
                    !fixture.downloaded("probe.txt"),
                    "denied download wrote into the ephemeral profile"
                );
                assert!(
                    fixture.seen.contains("https://example.com/probe.txt"),
                    "download attempt did not exercise the intercepted transport"
                );
                assert!(
                    fixture
                        .seen
                        .iter()
                        .all(|url| !url.starts_with("ws:") && !url.starts_with("wss:")),
                    "WebSocket escaped into the HTTP broker"
                );
                let expand = page
                    .references
                    .iter()
                    .find(|reference| reference.label == "Probe")
                    .unwrap()
                    .reference
                    .clone();
                fixture
                    .action(8, wire::Action::Expand { reference: expand })
                    .await;
                let navigated = fixture.completed(8).await.unwrap();
                assert_eq!(navigated.url, "https://example.com/expand-nav");
                assert!(
                    fixture.seen.contains("https://example.com/expand-nav"),
                    "expansion navigation bypassed the intercepted transport"
                );
                fixture.html(8, &navigated);
                fixture.action(9, wire::Action::Close).await;
                loop {
                    match fixture.message().await {
                        wire::Output::Completed {
                            id: 9,
                            result: Ok(None),
                        } => break,
                        message => fixture.broker(message).await,
                    }
                }
                assert!(child.wait().await.unwrap().success());
                return;
            }
            assert!(first.pending_requests, "held image request was hidden");
            assert!(fixture.html(1, &first).contains("Engine quote."));
            if scenario == "cancel_request" {
                let held = fixture.held.unwrap();
                fixture
                    .action(
                        2,
                        wire::Action::Open {
                            url: "https://example.com/next".into(),
                        },
                    )
                    .await;
                let next = fixture.completed(2).await.unwrap();
                assert!(fixture.html(2, &next).contains("Next quote."));
                assert!(
                    fixture.cancelled.contains(&held),
                    "navigation did not cancel its old request"
                );
                // Exercise a response that completed concurrently with cancel.
                fixture.respond(held, b"late", "image/png").await;
                fixture.action(3, wire::Action::Read).await;
                let read = fixture.completed(3).await.unwrap();
                fixture.html(3, &read);
                fixture.action(4, wire::Action::Close).await;
                loop {
                    match fixture.message().await {
                        wire::Output::Completed {
                            id: 4,
                            result: Ok(None),
                        } => break,
                        message => fixture.broker(message).await,
                    }
                }
                assert!(fixture.written.is_empty());
                assert!(child.wait().await.unwrap().success());
                return;
            }
            let details = first
                .references
                .iter()
                .find(|reference| reference.label == "Details")
                .unwrap()
                .reference
                .clone();
            let held = fixture.held.take().expect("missing held request");
            fixture.respond(held, b"image", "image/png").await;

            fixture
                .action(
                    2,
                    wire::Action::Expand {
                        reference: details.clone(),
                    },
                )
                .await;
            let expanded = fixture.completed(2).await.unwrap();
            assert!(fixture.html(2, &expanded).contains("<details open="));
            fixture
                .action(
                    3,
                    wire::Action::Scroll {
                        direction: secure_research::api::ScrollDirection::Down,
                    },
                )
                .await;
            let scrolled = fixture.completed(3).await.unwrap();
            let link = scrolled
                .references
                .iter()
                .find(|reference| reference.label == "Next")
                .unwrap()
                .reference
                .clone();
            fixture.html(3, &scrolled);
            fixture
                .action(4, wire::Action::FollowLink { reference: link })
                .await;
            let next = fixture.completed(4).await.unwrap();
            assert_eq!(next.url, "https://example.com/next");
            assert!(fixture.html(4, &next).contains("Next quote."));
            fixture
                .action(5, wire::Action::Expand { reference: details })
                .await;
            assert!(matches!(
                fixture.completed(5).await,
                Err(ErrorCode::StaleReference)
            ));
            fixture.action(6, wire::Action::Read).await;
            let read = fixture.completed(6).await.unwrap();
            assert!(fixture.html(6, &read).contains("Next quote."));
            fixture.action(7, wire::Action::Close).await;
            loop {
                match fixture.message().await {
                    wire::Output::Completed {
                        id: 7,
                        result: Ok(None),
                    } => break,
                    message => fixture.broker(message).await,
                }
            }
            assert!(child.wait().await.unwrap().success());
            assert!(
                read_frame::<_, wire::Output>(&mut fixture.output)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                fixture.written.is_empty(),
                "response files were not acknowledged"
            );
        };
        let result = tokio::time::timeout(Duration::from_secs(40), test).await;
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result.expect("private worker test timed out");
        drop(workspace);
        assert!(
            !workspace_path.exists(),
            "private worker workspace survived"
        );
    }
    println!(
        "PASS real browser worker IPC, CORS preflight and read POST, referrer guard, six actions, versioned references, pending requests, body acknowledgements and disconnect cleanup"
    );
}

struct Fixture {
    input: ChildStdin,
    output: ChildStdout,
    responses: Bodies,
    snapshots: Bodies,
    written: HashSet<u64>,
    held: Option<u64>,
    cancelled: HashSet<u64>,
    seen: HashSet<String>,
    rules: Vec<ReadPostRule>,
    post_probes: Vec<String>,
    root: PathBuf,
    hang: bool,
}

impl Fixture {
    fn new(input: ChildStdin, output: ChildStdout, root: &Path, rules: Vec<ReadPostRule>) -> Self {
        Self {
            input,
            output,
            responses: Bodies::open(&root.join("responses")).unwrap(),
            snapshots: Bodies::open(&root.join("output")).unwrap(),
            written: HashSet::new(),
            held: None,
            cancelled: HashSet::new(),
            seen: HashSet::new(),
            rules,
            post_probes: Vec::new(),
            root: root.to_owned(),
            hang: false,
        }
    }
    fn downloaded(&self, name: &str) -> bool {
        fn contains(root: &Path, name: &str) -> bool {
            std::fs::read_dir(root).is_ok_and(|entries| {
                entries.filter_map(std::result::Result::ok).any(|entry| {
                    entry.file_name() == name
                        || (entry.file_type().is_ok_and(|kind| kind.is_dir())
                            && contains(&entry.path(), name))
                })
            })
        }
        contains(&self.root.join("scratch"), name)
    }
    async fn action(&mut self, id: u64, action: wire::Action) {
        write_frame(&mut self.input, &wire::Input::Action { id, action })
            .await
            .unwrap();
    }
    async fn message(&mut self) -> wire::Output {
        read_frame(&mut self.output)
            .await
            .unwrap()
            .expect("unexpected worker EOF")
    }
    async fn completed(&mut self, expected: u64) -> Result<wire::Snapshot, ErrorCode> {
        loop {
            let message = self.message().await;
            if let wire::Output::Completed { id, result } = message {
                assert_eq!(id, expected);
                return result.map(|snapshot| {
                    let snapshot = snapshot.unwrap();
                    snapshot.validate(8 * MIB).unwrap();
                    snapshot
                });
            }
            self.broker(message).await;
        }
    }
    fn html(&self, id: u64, snapshot: &wire::Snapshot) -> String {
        let html = self
            .snapshots
            .read(id, snapshot.html_bytes, &snapshot.html_sha256, 8 * MIB)
            .unwrap();
        self.snapshots.remove(id).unwrap();
        String::from_utf8(html).unwrap()
    }
    async fn respond(&mut self, id: u64, body: &[u8], media: &str) {
        self.respond_with(id, 200, body, media, false).await;
    }
    async fn respond_with(&mut self, id: u64, status: u16, body: &[u8], media: &str, cors: bool) {
        assert!(self.written.insert(id), "duplicate HTTP request ID");
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", media.parse().unwrap());
        if cors {
            headers.insert(
                "access-control-allow-origin",
                "https://example.com".parse().unwrap(),
            );
            headers.insert("access-control-allow-methods", "POST".parse().unwrap());
            headers.insert(
                "access-control-allow-headers",
                "content-type".parse().unwrap(),
            );
        }
        let reply = wire::HttpReply::from_response(
            &secure_research::http::HttpResponse {
                status,
                headers,
                body: body.to_vec(),
            },
            8 * MIB,
        )
        .unwrap();
        self.responses.write(id, body, 8 * MIB).unwrap();
        write_frame(
            &mut self.input,
            &wire::Input::Http {
                id,
                result: Ok(reply),
            },
        )
        .await
        .unwrap();
    }
    async fn broker(&mut self, message: wire::Output) {
        match message {
            wire::Output::Http { id, request: input } => {
                let checked = request::check(&input, &self.rules).unwrap();
                if checked.target.as_str() == "https://other.example/pixel" {
                    let raw_referrer = input
                        .headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("referer"))
                        .map(|(_, value)| value.as_str());
                    assert_eq!(
                        raw_referrer,
                        Some("https://example.com/referrer-page?private=secret")
                    );
                    assert_eq!(checked.headers["referer"], "https://example.com/");
                }
                self.seen.insert(checked.target.as_str().to_owned());
                if checked.target.as_str() == "https://other.example/read" {
                    self.post_probes.push(checked.method.as_str().to_owned());
                    match checked.method {
                        http::Method::OPTIONS => {
                            assert!(!checked.headers.contains_key("cookie"));
                            assert!(!checked.headers.contains_key("referer"));
                            assert_eq!(checked.headers["access-control-request-method"], "POST");
                            assert_eq!(
                                checked.headers["access-control-request-headers"],
                                "content-type"
                            );
                            self.respond_with(id, 204, b"", "text/plain", true).await;
                        }
                        http::Method::POST => {
                            assert_eq!(checked.body, br#"{"query":"article"}"#);
                            self.respond_with(id, 200, b"Read quote.", "text/plain", true)
                                .await;
                        }
                        other => panic!("unexpected read method {other}"),
                    }
                    return;
                }
                match checked.target.as_str() {
                    "https://example.com/engine" if self.hang => self.respond(id, b"<script>while(true){}</script>", "text/html").await,
                    "https://example.com/engine" => self.respond(id, br#"<title>Engine</title><p>Engine quote.</p><img src='/held'><a href='/next'>Next</a><details><summary>Details</summary>More text</details><div style='height:3000px'>End</div>"#, "text/html").await,
                    "https://example.com/referrer-page?private=secret" => self.respond(id, br#"<meta name='referrer' content='unsafe-url'><title>Referrer</title><img src='https://other.example/pixel'>"#, "text/html").await,
                    "https://example.com/preflight-page" => self.respond(id, b"<title>Preflight</title><p id='status'>pending</p><script>fetch('https://other.example/read', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{\"query\":\"article\"}'}).then(response => response.text()).then(text => document.getElementById('status').textContent = text).catch(() => document.getElementById('status').textContent = 'blocked');</script>", "text/html").await,
                    "https://other.example/pixel" => self.respond(id, b"image", "image/png").await,
                    "https://example.com/next" => self.respond(id, b"<title>Next</title><p>Next quote.</p>", "text/html").await,
                    "https://example.com/adversarial-sw" => self.respond(id, b"<title>Service worker probe</title><p id='status'>pending</p><script>Promise.race([navigator.serviceWorker.register('/sw.js').then(() => 'registered', () => 'rejected'), new Promise(resolve => setTimeout(() => resolve('blocked'), 100))]).then(value => status.textContent = value);</script>", "text/html").await,
                    "https://example.com/adversarial-worker" => self.respond(id, b"<title>Worker probe</title><script>new Worker('/worker.js');</script>", "text/html").await,
                    "https://example.com/adversarial-popup" => self.respond(id, b"<title>Popup probe</title><script>open('/popup');</script>", "text/html").await,
                    "https://example.com/adversarial" => self.respond(id, br#"<title>Adversarial</title><p>Adversarial page.</p><a id='download' href='/probe.txt' download>Download</a><button type='button' aria-expanded='false' aria-controls='panel'>Probe</button><div id='panel'>Panel</div><script>try { new WebSocket('wss://example.com/socket'); } catch (_) {} download.click(); document.querySelector('button').addEventListener('click', () => { location.href = '/expand-nav'; });</script>"#, "text/html").await,
                    "https://example.com/sw.js" => self.respond(id, b"self.addEventListener('fetch', event => event.respondWith(new Response('unexpected')));", "text/javascript").await,
                    "https://example.com/worker.js" => self.respond(id, b"postMessage('worker');", "text/javascript").await,
                    "https://example.com/probe.txt" => self.respond(id, b"download", "text/plain").await,
                    "https://example.com/expand-nav" => self.respond(id, b"<title>Expanded navigation</title><p>Expansion navigation remained intercepted.</p>", "text/html").await,
                    "https://example.com/held" => { assert!(self.held.replace(id).is_none()); },
                    "https://example.com/favicon.ico" => self.respond(id, b"", "image/png").await,
                    _ => panic!("unexpected synthetic request"),
                }
            }
            wire::Output::Consumed { id } => {
                assert!(self.written.remove(&id), "unsolicited body acknowledgement");
                self.responses.remove(id).unwrap();
            }
            wire::Output::CancelHttp { id } => {
                self.cancelled.insert(id);
            }
            _ => panic!("unexpected worker message"),
        }
    }
}
