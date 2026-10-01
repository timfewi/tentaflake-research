//! Real Chromium in a private root/PID/network namespace. Synthetic responses
//! exercise interception without making any provider or public network call.
use base64::Engine;
use chromiumoxide::cdp::{
    browser_protocol::{browser, fetch, page, target},
    js_protocol::runtime,
};
use secure_research::{
    api::ScrollDirection,
    browser::{
        body::Bodies,
        launch::{Launched, Settings},
        read::Reader,
        request,
        sandbox::{SandboxConfig, Workspace},
        targets::Targets,
        wire,
    },
    config::{MIB, ReadPostOperation, ReadPostRule},
    error::ErrorCode,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let arguments: Vec<_> = std::env::args().collect();
            if arguments.get(1).is_some_and(|value| value == "--probe") {
                probe(&arguments[2], &arguments[3], &arguments[4]).await;
            } else {
                check().await;
            }
        });
}

fn required(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("required test setting: {name}"))
}

async fn check() {
    let config = SandboxConfig {
        worker: std::env::current_exe().unwrap(),
        bubblewrap: required("RESEARCH_TEST_BWRAP"),
        chromium_sandbox: required("RESEARCH_TEST_CHROMIUM_SANDBOX"),
        fontconfig: required("RESEARCH_TEST_FONTCONFIG"),
        store_paths: std::fs::read_to_string(required("RESEARCH_TEST_CHROMIUM_CLOSURE"))
            .unwrap()
            .lines()
            .map(PathBuf::from)
            .collect(),
    };
    let chromium = required("RESEARCH_TEST_CHROMIUM");
    let root = tempfile::tempdir().unwrap();
    let canary = root.path().join("host-secret");
    std::fs::write(&canary, b"host-only").unwrap();
    let host_network = std::fs::read_link("/proc/self/ns/net").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let workspace = Workspace::new(root.path()).unwrap();
    let workspace_path = workspace.root().to_owned();
    std::fs::write(workspace.root().join("responses/canary"), b"read-only").unwrap();
    let responses = Bodies::open(&workspace.root().join("responses")).unwrap();
    responses.write(1, b"read reply", 1024).unwrap();
    std::fs::write(
        workspace.root().join("responses/host-netns"),
        host_network.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    let mut command = workspace.command(&config, None).unwrap();
    command
        .env("RESEARCH_TEST_SECRET", "must-not-reach-worker")
        .args(["--", "/worker", "--probe"])
        .arg(chromium)
        .arg(&canary)
        .arg(listener.local_addr().unwrap().to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(45), child.wait()).await;
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    assert!(
        result.expect("browser timeout").unwrap().success(),
        "isolated browser probe failed"
    );
    assert_eq!(
        std::fs::read(workspace.root().join("output/passed")).unwrap(),
        b"ok"
    );
    assert_eq!(
        std::fs::read(workspace.root().join("scratch/tmp/shm-probe")).unwrap(),
        b"shared-quota"
    );
    let frame = secure_research::worker::read_bounded(
        &workspace.root().join("output/snapshot.frame"),
        1024 * 1024,
    )
    .unwrap();
    let message: wire::Output = secure_research::protocol::read_frame(&mut &frame[..])
        .await
        .unwrap()
        .unwrap();
    let wire::Output::Completed {
        id,
        result: Ok(Some(snapshot)),
    } = message
    else {
        panic!("unexpected snapshot frame");
    };
    snapshot.validate(8 * MIB).unwrap();
    let html = Bodies::open(&workspace.root().join("output"))
        .unwrap()
        .read(id, snapshot.html_bytes, &snapshot.html_sha256, 8 * MIB)
        .unwrap();
    assert!(
        std::str::from_utf8(&html)
            .unwrap()
            .contains("Exact é 👩‍🔬 quote.")
    );
    drop(workspace);
    assert!(!workspace_path.exists(), "browser profile survived cleanup");
    println!(
        "PASS real Chromium startup, sandbox, synthetic JS subrequest, private mounts/network and profile cleanup"
    );
}

async fn probe(chromium: &str, canary: &str, host_loopback: &str) {
    assert!(std::env::var("RESEARCH_TEST_SECRET").is_err());
    assert!(std::fs::read(canary).is_err());
    assert!(!Path::new("/home").exists());
    assert!(!Path::new("/run/credentials").exists());
    assert!(std::fs::write("/responses/canary", b"overwrite").is_err());
    for path in ["/escape", "/nix/escape", "/dev/escape"] {
        assert!(
            std::fs::write(path, b"unaccounted").is_err(),
            "writable auxiliary filesystem: {path}"
        );
    }
    std::fs::write("/dev/shm/shm-probe", b"shared-quota").unwrap();
    let private_network = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_ne!(
        private_network.as_os_str().as_encoded_bytes(),
        std::fs::read("/responses/host-netns").unwrap()
    );
    let interfaces = std::fs::read_to_string("/proc/net/dev").unwrap();
    assert!(
        interfaces
            .lines()
            .filter_map(|line| line.split_once(':'))
            .all(|(name, _)| name.trim() == "lo"),
        "unexpected network interface"
    );
    assert!(
        std::net::TcpStream::connect_timeout(
            &host_loopback.parse().unwrap(),
            Duration::from_millis(100)
        )
        .is_err()
    );
    let stop = CancellationToken::new();
    let settings = Settings {
        chromium: chromium.into(),
        width: 1365,
        height: 768,
        operation_seconds: 10,
        html_bytes: 8 * MIB,
        requests: 32,
        actions: 8,
        locale: "en-US".into(),
        timezone: "UTC".into(),
        accept_language: "en-US,en;q=0.9".into(),
    };
    let (launched, mut events) = Launched::start(&settings, &stop)
        .await
        .expect("Chromium startup");
    let cdp = launched.cdp.clone();
    assert_eq!(
        std::fs::read_link(format!("/proc/{}/ns/net", launched.child.id().unwrap())).unwrap(),
        private_network
    );
    let command = std::fs::read(format!("/proc/{}/cmdline", launched.child.id().unwrap())).unwrap();
    let arguments: Vec<_> = command.split(|byte| *byte == 0).collect();
    let mut keys = std::collections::HashSet::new();
    for argument in arguments
        .iter()
        .filter(|argument| argument.starts_with(b"--"))
    {
        assert!(
            keys.insert(argument.split(|byte| *byte == b'=').next().unwrap()),
            "duplicate Chromium switch"
        );
    }
    assert!(
        !arguments
            .iter()
            .any(|argument| argument.starts_with(b"----"))
    );
    for required in [
        "--no-startup-window",
        "--disable-background-networking",
        "--disable-quic",
        "--disable-component-extensions-with-background-pages",
        "--proxy-server=http://127.0.0.1:9",
        "--proxy-bypass-list=<-loopback>",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--lang=en-US",
        "--accept-lang=en-US,en;q=0.9",
    ] {
        assert!(
            arguments.contains(&required.as_bytes()),
            "missing effective flag: {required}"
        );
    }
    let version = cdp
        .command::<browser::GetVersionParams>(None, json!({}))
        .await
        .unwrap();
    assert!(
        version.product.contains("153."),
        "unexpected pinned Chromium"
    );
    assert_eq!(
        version.user_agent.replace("HeadlessChrome/", "Chrome/"),
        secure_research::config::DEFAULT_USER_AGENT,
        "HTTP and browser defaults must use the pinned Chromium platform and version"
    );
    // Exercise the browser's native network stack without Fetch interception.
    // Even loopback must use the deliberately unreachable proxy, not Chromium's
    // usual implicit bypass. A real listener would catch an ineffective flag.
    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let isolated_target = cdp
        .command::<target::CreateTargetParams>(None, json!({"url":"about:blank"}))
        .await
        .unwrap();
    let isolated_session = cdp
        .command::<target::AttachToTargetParams>(
            None,
            json!({"targetId":isolated_target.target_id,"flatten":true}),
        )
        .await
        .unwrap();
    for url in [
        format!("http://{}/canary", local_listener.local_addr().unwrap()),
        "http://example.com/".into(),
    ] {
        let result = cdp
            .command::<page::NavigateParams>(
                Some(isolated_session.session_id.as_ref()),
                json!({"url":url}),
            )
            .await
            .unwrap();
        assert_eq!(
            result.error_text.as_deref(),
            Some("net::ERR_PROXY_CONNECTION_FAILED")
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), local_listener.accept())
            .await
            .is_err(),
        "Chromium bypassed proxy for loopback"
    );
    cdp.command::<target::CloseTargetParams>(None, json!({"targetId":isolated_target.target_id}))
        .await
        .unwrap();
    while events.try_recv().is_ok() {}
    println!(
        "PASS actual flags, distinct network namespace with loopback only, native Chromium proxy refusal for local/public targets"
    );
    let mut targets = Targets::create(cdp.clone(), &settings, &mut events)
        .await
        .unwrap();
    let session = targets.main_session().to_owned();
    let broker = cdp.clone();
    let browser_agent = version.user_agent.clone();
    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
    let responder = tokio::spawn(async move {
        let mut observed_tx = Some(observed_tx);
        let mut observed = Vec::new();
        let mut saw_popup = false;
        let mut saw_paused_worker = false;
        let rules = [ReadPostRule {
            origin: "https://example.com".into(),
            path: "/read".into(),
            max_bytes: 128,
            operation: ReadPostOperation::ExactBody {
                sha256: secure_research::policy::sha256(br#"{"query":"article"}"#),
                content_type: "application/json".into(),
            },
        }];
        while let Some(event) = events.recv().await {
            if broker.stopped().is_cancelled() {
                break;
            }
            if event.method == "Target.attachedToTarget" {
                saw_popup |= event.params["targetInfo"]["type"] == "page"
                    && event.params["targetInfo"].get("openerId").is_some();
                saw_paused_worker |= event.params["targetInfo"]["type"] == "worker"
                    && event.params["waitingForDebugger"] == true;
            }
            if targets
                .handle(&event)
                .await
                .unwrap_or_else(|error| panic!("target control {event:?}: {error:?}"))
            {
                continue;
            }
            if event.method != "Fetch.requestPaused" {
                continue;
            }
            assert!(targets.owns_session(event.session.as_deref()));
            let url = event.params["request"]["url"].as_str().unwrap().to_owned();
            let paused: fetch::EventRequestPaused =
                serde_json::from_value(event.params.clone()).unwrap();
            let checked =
                request::from_cdp(&paused.request, paused.resource_type.as_ref(), false, 0)
                    .and_then(|request| request::check(&request, &rules));
            if let Err(error) = checked {
                assert!(
                    url == "https://example.com/write" || url == "http://127.0.0.1/frame-private"
                );
                assert!(matches!(
                    error,
                    ErrorCode::PolicyDenied | ErrorCode::DestinationDenied
                ));
                broker
                    .command::<fetch::FailRequestParams>(
                        event.session.as_deref(),
                        json!({
                            "requestId":event.params["requestId"], "errorReason":"BlockedByClient",
                        }),
                    )
                    .await
                    .unwrap();
                observed.push(url);
                continue;
            }
            if url == "https://example.com/" {
                assert_eq!(
                    checked
                        .unwrap()
                        .headers
                        .get("user-agent")
                        .and_then(|value| value.to_str().ok()),
                    Some(browser_agent.as_str()),
                    "browser network request lost its actual User-Agent"
                );
            }
            let (body, media) = match url.as_str() {
                "https://example.com/" => (
                    r#"<title>Fixture</title><p id='result'>pending</p>
                    <a id='link' href='/next' onclick='document.body.dataset.clicked="yes"'>Next page</a>
                    <a href='http://127.0.0.1/private'>Private destination</a>
                    <details><summary>More details</summary><p>Expanded quote</p></details>
                    <button type='button' aria-expanded='false' aria-controls='extra' onclick='this.setAttribute("aria-expanded","true");document.getElementById("extra").hidden=false'>More text</button>
                    <p id='extra' hidden>Extra quote</p>
                    <form><button type='button' aria-expanded='false' aria-controls='extra'>Forbidden form action</button></form>
                    <div style='height:3000px'>Long article</div>
                    <script>fetch('/data').then(r=>r.text()).then(t=>document.getElementById('result').textContent=t);
                    globalThis.__research_read_v1={version:'forged',nodes:[]};
                    Element.prototype.getClientRects=()=>[];</script>"#,
                    "text/html",
                ),
                "https://example.com/data" => ("Exact é 👩‍🔬 quote.", "text/plain"),
                "https://example.com/read" => ("read reply", "text/plain"),
                "https://example.org/frame" => (
                    r#"<p>Cross-site frame</p><script>
                    fetch('/frame-data').then(r=>r.text()).then(t=>parent.postMessage(t,'*'));
                    fetch('http://127.0.0.1/frame-private').catch(()=>{});
                    </script>"#,
                    "text/html",
                ),
                "https://example.org/frame-data" => ("frame-ready", "text/plain"),
                _ => ("", "text/plain"),
            };
            let body_bytes = if url == "https://example.com/read" {
                Bodies::open(Path::new("/responses"))
                    .unwrap()
                    .read(1, 10, &secure_research::policy::sha256(b"read reply"), 1024)
                    .unwrap()
            } else {
                body.as_bytes().to_vec()
            };
            let mut response_headers = http::HeaderMap::new();
            response_headers.insert("content-type", media.parse().unwrap());
            let reply = wire::HttpReply::from_response(
                &secure_research::http::HttpResponse {
                    status: 200,
                    headers: response_headers,
                    body: body_bytes.clone(),
                },
                8 * MIB,
            )
            .unwrap();
            reply.validate(8 * MIB).unwrap();
            broker
                .command::<fetch::FulfillRequestParams>(
                    event.session.as_deref(),
                    json!({
                        "requestId":event.params["requestId"], "responseCode":200,
                        "responseHeaders":reply.headers.iter().map(|(name,value)|json!({"name":name,"value":value})).collect::<Vec<_>>(),
                        "body":base64::engine::general_purpose::STANDARD.encode(body_bytes),
                    }),
                )
                .await
                .unwrap();
            observed.push(url);
            if observed.iter().any(|url| url.ends_with("/data"))
                && let Some(sender) = observed_tx.take()
            {
                let _ = sender.send(observed.clone());
            }
        }
        (
            observed,
            targets.blocked_targets,
            saw_popup,
            saw_paused_worker,
        )
    });
    let navigation = cdp
        .command::<page::NavigateParams>(Some(&session), json!({"url":"https://example.com/"}))
        .await
        .unwrap();
    assert!(navigation.error_text.is_none(), "navigation failed");
    let observed = tokio::time::timeout(Duration::from_secs(10), observed_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(observed.iter().any(|url| url == "https://example.com/"));
    let text = cdp.command::<runtime::EvaluateParams>(Some(&session), json!({
        "expression":"new Promise((resolve,reject)=>{let tries=0; const timer=setInterval(()=>{if(document.body.innerText.includes('quote.')){clearInterval(timer);resolve(document.body.innerText);}else if(++tries>100){clearInterval(timer);reject('fixture timeout');}},20);})",
        "awaitPromise":true,"returnByValue":true,
    })).await.unwrap();
    assert!(text.exception_details.is_none());
    assert!(
        text.result
            .value
            .unwrap()
            .as_str()
            .unwrap()
            .contains("Exact é 👩‍🔬 quote.")
    );
    let post = cdp.command::<runtime::EvaluateParams>(Some(&session), json!({
        "expression":r#"Promise.all([fetch('/read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'article'})}).then(r=>r.text()),fetch('/write',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mutation:'buy'})}).then(()=> 'unexpected').catch(()=> 'blocked')])"#,
        "awaitPromise":true,"returnByValue":true,
    })).await.unwrap();
    assert!(post.exception_details.is_none());
    assert_eq!(post.result.value, Some(json!(["read reply", "blocked"])));
    let mut reader = Reader::new(cdp.clone(), session.clone(), settings.html_bytes);
    let first = reader.read().await.unwrap();
    first.metadata.validate(settings.html_bytes).unwrap();
    Bodies::open(Path::new("/output"))
        .unwrap()
        .write(1, &first.html, settings.html_bytes)
        .unwrap();
    let mut frame = Vec::new();
    secure_research::protocol::write_frame(
        &mut frame,
        &wire::Output::Completed {
            id: 1,
            result: Ok(Some(first.metadata.clone())),
        },
    )
    .await
    .unwrap();
    std::fs::write("/output/snapshot.frame", frame).unwrap();
    assert!(
        first.metadata.truncated_references,
        "private link omission must be visible"
    );
    assert_eq!(
        first.metadata.references.len(),
        3,
        "form and private targets must not be actionable"
    );
    let link = first
        .metadata
        .references
        .iter()
        .find(|item| item.label == "Next page")
        .unwrap()
        .reference
        .clone();
    assert_eq!(
        reader.follow_link(&link).await.unwrap().as_str(),
        "https://example.com/next"
    );
    let clicked = cdp
        .command::<runtime::EvaluateParams>(
            Some(&session),
            json!({"expression":"document.body.dataset.clicked || 'no'", "returnByValue":true}),
        )
        .await
        .unwrap();
    assert_eq!(
        clicked.result.value,
        Some(json!("no")),
        "following must not click the page element"
    );
    cdp.command::<runtime::EvaluateParams>(
        Some(&session),
        json!({"expression":"document.getElementById('link').href='/changed'"}),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            reader.follow_link(&link).await,
            Err(ErrorCode::StaleReference)
        ),
        "changed URL must invalidate the observed reference"
    );
    let second = reader.read().await.unwrap();
    assert!(
        matches!(
            reader.follow_link(&link).await,
            Err(ErrorCode::StaleReference)
        ),
        "new snapshot must expire previous references"
    );
    let details = second
        .metadata
        .references
        .iter()
        .find(|item| item.label == "More details")
        .unwrap()
        .reference
        .clone();
    reader.expand(&details).await.unwrap();
    assert!(matches!(
        reader.expand(&details).await,
        Err(ErrorCode::StaleReference)
    ));
    let third = reader.read().await.unwrap();
    assert!(
        !third
            .metadata
            .references
            .iter()
            .any(|item| item.label == "More details")
    );
    let more = third
        .metadata
        .references
        .iter()
        .find(|item| item.label == "More text")
        .unwrap()
        .reference
        .clone();
    cdp.command::<runtime::EvaluateParams>(Some(&session), json!({"expression":"{const target=document.getElementById('extra');target.replaceWith(target.cloneNode(true));}"})).await.unwrap();
    assert!(
        matches!(reader.expand(&more).await, Err(ErrorCode::StaleReference)),
        "replaced content target must invalidate expansion"
    );
    let replaced = reader.read().await.unwrap();
    let more = replaced
        .metadata
        .references
        .iter()
        .find(|item| item.label == "More text")
        .unwrap()
        .reference
        .clone();
    reader.expand(&more).await.unwrap();
    let fourth = reader.read().await.unwrap();
    assert!(
        !fourth
            .metadata
            .references
            .iter()
            .any(|item| item.label == "More text")
    );
    reader.scroll(ScrollDirection::Down).await.unwrap();
    let position = cdp
        .command::<runtime::EvaluateParams>(
            Some(&session),
            json!({"expression":"window.scrollY", "returnByValue":true}),
        )
        .await
        .unwrap();
    assert!(position.result.value.unwrap().as_f64().unwrap() > 0.0);
    reader.read().await.unwrap();
    reader.scroll(ScrollDirection::Up).await.unwrap();
    let position = cdp
        .command::<runtime::EvaluateParams>(
            Some(&session),
            json!({"expression":"window.scrollY", "returnByValue":true}),
        )
        .await
        .unwrap();
    assert_eq!(position.result.value.unwrap().as_f64(), Some(0.0));
    let profile = cdp.command::<runtime::EvaluateParams>(Some(&session), json!({
        "expression":"({width:innerWidth,height:innerHeight,screenWidth:screen.width,screenHeight:screen.height,language:navigator.language,zone:Intl.DateTimeFormat().resolvedOptions().timeZone,agent:navigator.userAgent})", "returnByValue":true,
    })).await.unwrap().result.value.unwrap();
    assert_eq!(profile["width"], 1365);
    assert_eq!(profile["height"], 768);
    assert_eq!(profile["screenWidth"], 1365);
    assert_eq!(profile["screenHeight"], 768);
    assert_eq!(profile["language"], "en-US");
    assert_eq!(profile["zone"], "UTC");
    assert_eq!(profile["agent"], version.user_agent);
    let frame = cdp.command::<runtime::EvaluateParams>(Some(&session), json!({
        "expression":r#"new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject('frame timeout'),5000);addEventListener('message',event=>{if(event.origin==='https://example.org'&&event.data==='frame-ready'){clearTimeout(timer);resolve(event.data);}});const frame=document.createElement('iframe');frame.src='https://example.org/frame';document.body.append(frame);})"#,
        "returnByValue":true,"awaitPromise":true,
    })).await.unwrap();
    assert!(
        frame.exception_details.is_none(),
        "frame setup failed: {:?}",
        frame.exception_details
    );
    assert_eq!(frame.result.value, Some(json!("frame-ready")));
    cdp.command::<runtime::EvaluateParams>(
        Some(&session),
        json!({
            "expression":r#"window.open('https://example.net/popup');"#,
            "userGesture":true,
        }),
    )
    .await
    .unwrap();
    // Workers remain attached and paused: Chromium cannot close them separately.
    // Popups must close. The final namespace cleanup reaps every target.
    let mut cleaned = false;
    for _ in 0..100 {
        let list = cdp
            .command::<target::GetTargetsParams>(None, json!({}))
            .await
            .unwrap();
        if !list
            .target_infos
            .iter()
            .any(|info| info.url.contains("example.net/popup"))
        {
            cleaned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(cleaned, "popup not closed");
    let before_navigation = reader.read().await.unwrap();
    let old_link = before_navigation
        .metadata
        .references
        .iter()
        .find(|item| item.label == "Next page")
        .unwrap()
        .reference
        .clone();
    cdp.command::<runtime::EvaluateParams>(
        Some(&session),
        json!({"expression":"history.pushState({}, '', '/history-change')"}),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            reader.follow_link(&old_link).await,
            Err(ErrorCode::StaleReference)
        ),
        "history navigation must invalidate references"
    );
    let before_reload = reader.read().await.unwrap();
    let old_link = before_reload
        .metadata
        .references
        .iter()
        .find(|item| item.label == "Next page")
        .unwrap()
        .reference
        .clone();
    cdp.command::<page::NavigateParams>(
        Some(&session),
        json!({"url":"https://example.com/replacement"}),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            reader.follow_link(&old_link).await,
            Err(ErrorCode::StaleReference)
        ),
        "new document must expire its previous execution context"
    );
    println!(
        "PASS isolated-world snapshots, stale/mutated references, bounded expansion, no link clicks or form controls, scrolling"
    );
    // Chromium may hold the creating renderer while its worker is paused.
    // Trigger asynchronously after reading; the supervisor must still be able
    // to observe and destroy the paused worker and all renderer descendants.
    cdp.command::<runtime::EvaluateParams>(Some(&session), json!({
        "expression":r#"setTimeout(()=>new Worker(URL.createObjectURL(new Blob(["fetch('https://example.com/worker-leak')"],{type:'text/javascript'}))),0);"#,
    })).await.unwrap();
    let mut held_worker = false;
    for _ in 0..100 {
        let list = cdp
            .command::<target::GetTargetsParams>(None, json!({}))
            .await
            .unwrap();
        if list
            .target_infos
            .iter()
            .any(|info| info.r#type == "worker" && info.attached)
        {
            held_worker = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_worker, "worker was not held");
    // Require a filter added by Chromium even if the test runner itself
    // already inherited a host seccomp filter.
    let inherited_filters = seccomp_filters(&std::fs::read_to_string("/proc/self/status").unwrap());
    let mut renderers = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(command) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        // Chromium can rewrite argv into a single process-title string.
        if command
            .split(|b| *b == 0 || b.is_ascii_whitespace())
            .any(|arg| arg == b"--type=renderer")
        {
            assert!(
                !command
                    .split(|b| *b == 0 || b.is_ascii_whitespace())
                    .any(|arg| arg == b"--no-sandbox")
            );
            let status = std::fs::read_to_string(entry.path().join("status")).unwrap();
            assert!(status.lines().any(|line| line == "Seccomp:\t2"));
            assert!(
                seccomp_filters(&status) > inherited_filters,
                "renderer has no additional seccomp filter"
            );
            assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
            renderers.push(pid);
        }
    }
    assert!(!renderers.is_empty(), "no sandboxed renderer observed");
    launched.close().await;
    let (requests, blocked, saw_popup, saw_paused_worker) = responder.await.unwrap();
    assert!(
        saw_popup && saw_paused_worker,
        "adversarial targets were not exercised"
    );
    assert!(
        blocked >= 2,
        "worker and popup were not observed and blocked"
    );
    assert!(
        requests
            .iter()
            .any(|url| url == "https://example.org/frame-data")
    );
    assert!(
        !requests
            .iter()
            .any(|url| url.ends_with("worker-leak") || url.ends_with("/popup")),
        "forbidden target reached broker"
    );
    for _ in 0..100 {
        if renderers
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        renderers
            .iter()
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists()),
        "renderer survived close"
    );
    std::fs::write("/output/passed", b"ok").unwrap();
}

fn seccomp_filters(status: &str) -> u32 {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:").map(str::trim))
        .expect("kernel does not expose seccomp filter counts")
        .parse()
        .unwrap()
}
