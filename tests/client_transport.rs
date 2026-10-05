//! Actual client binaries over a synthetic Unix peer, without service libraries.
use base64::{Engine, engine::general_purpose::STANDARD};
use secure_research::protocol::{self, Operation, Outcome, Request, Response, Tool, VERSION};
use serde_json::{Value, json};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
};

fn listener() -> (TempDir, PathBuf, UnixListener) {
    // Socket paths must stay short even when the check runner's TMPDIR is long.
    let root = tempfile::Builder::new()
        .prefix("research-client-")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = root.path().join("socket");
    let listener = UnixListener::bind(&socket).unwrap();
    (root, socket, listener)
}

async fn reply(stream: &mut UnixStream, request: Request, value: Value) {
    protocol::write_frame(
        stream,
        &Response {
            version: VERSION,
            id: request.id,
            outcome: Outcome::Result { value },
        },
    )
    .await
    .unwrap();
}

async fn hello(listener: UnixListener) -> UnixStream {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap()
        .0;
    let request: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
    assert_eq!(request.version, VERSION);
    assert!(matches!(request.operation, Operation::Hello));
    reply(
        &mut stream,
        request,
        json!({"version":VERSION,"max_frame":protocol::MAX_FRAME,"tools":protocol::TOOLS}),
    )
    .await;
    stream
}

#[tokio::test]
async fn mcp_binary_exposes_five_tools_and_forwards_typed_arguments() {
    let (_root, socket, listener) = listener();
    let peer = tokio::spawn(async move {
        let mut stream = hello(listener).await;
        let request: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
        let Operation::Call { tool, arguments } = &request.operation else {
            panic!("expected tool call");
        };
        assert_eq!(*tool, Tool::ResearchJob);
        assert_eq!(arguments["operation"], "start");
        assert_eq!(arguments["limits"]["queries"], 0);
        reply(&mut stream, request, json!({"job":{"id":"fixture-job"}})).await;
        assert!(
            protocol::read_frame::<_, Request>(&mut stream)
                .await
                .unwrap()
                .is_none()
        );
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_research-client"))
        .arg("--socket")
        .arg(socket)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    let messages = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"research_job","arguments":{"operation":"start","limits":{"queries":0}}}}),
    ];
    for message in messages {
        input
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
        input.flush().await.unwrap();
        if message.get("id").is_none() {
            continue;
        }
        let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], message["id"]);
        assert!(reply.get("error").is_none(), "{reply}");
        if message["id"] == 2 {
            let mut names: Vec<_> = reply["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect();
            names.sort_unstable();
            assert_eq!(
                names,
                [
                    "research_browser",
                    "research_fetch",
                    "research_job",
                    "research_read",
                    "research_search"
                ]
            );
        } else if message["id"] == 3 {
            assert_eq!(
                reply["result"]["structuredContent"]["job"]["id"],
                "fixture-job"
            );
        }
    }
    drop(input);
    let result = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(result.status.success(), "{:?}", result.stderr);
    assert!(result.stderr.is_empty());
    tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn curl_binary_returns_exact_bytes_through_unix_transport() {
    let (_root, socket, listener) = listener();
    let body = b"raw\0binary\xff\n";
    let peer = tokio::spawn(async move {
        let mut stream = hello(listener).await;
        for step in 0..5 {
            let request: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
            let Operation::Call { tool, arguments } = &request.operation else {
                panic!("expected tool call");
            };
            let value = match step {
                0 => {
                    assert_eq!(*tool, Tool::ResearchJob);
                    assert_eq!(arguments["operation"], "start");
                    assert_eq!(arguments["limits"]["micro_usd"], 0);
                    assert_eq!(arguments["limits"]["queries"], 0);
                    assert_eq!(arguments["limits"]["browser_actions"], 0);
                    json!({"job":{"id":"fixture-job"}})
                }
                1 => {
                    assert_eq!(*tool, Tool::ResearchFetch);
                    assert_eq!(arguments["urls"], json!(["https://example.org/body"]));
                    assert_eq!(arguments["mode"], "http");
                    json!({"items":[{"state":"success","error":null,"data":{"raw_source_id":"fixture-source"}}]})
                }
                2 => {
                    assert_eq!(*tool, Tool::ResearchRead);
                    assert_eq!(arguments["kind"], "metadata");
                    json!({"representations":[{"kind":"http_entity","id":"fixture-body"}]})
                }
                3 => {
                    assert_eq!(*tool, Tool::ResearchRead);
                    assert_eq!(arguments["representation_id"], "fixture-body");
                    json!({"encoding":"base64_bytes","content":STANDARD.encode(body),"start":0,"end":body.len(),"total":body.len(),"next_cursor":null})
                }
                _ => {
                    assert_eq!(*tool, Tool::ResearchJob);
                    assert_eq!(arguments["operation"], "finish");
                    json!({})
                }
            };
            reply(&mut stream, request, value).await;
        }
        assert!(
            protocol::read_frame::<_, Request>(&mut stream)
                .await
                .unwrap()
                .is_none()
        );
    });
    let child = Command::new(env!("CARGO_BIN_EXE_research-curl"))
        .arg("--socket")
        .arg(socket)
        .args(["-fsSL", "https://example.org/body#fragment"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(result.status.success(), "{:?}", result.stderr);
    assert_eq!(result.stdout, body);
    assert!(result.stderr.is_empty());
    tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn curl_binary_rejects_an_incompatible_unix_peer() {
    let (_root, socket, listener) = listener();
    let peer = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap().0;
        let request: Request = protocol::read_frame(&mut stream).await.unwrap().unwrap();
        reply(&mut stream, request, json!({"version":VERSION + 1})).await;
    });
    let child = Command::new(env!("CARGO_BIN_EXE_research-curl"))
        .arg("--socket")
        .arg(socket)
        .arg("https://example.org/")
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!result.stderr.is_empty());
    tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
}

async fn run_curl(socket: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    let child = Command::new(env!("CARGO_BIN_EXE_research-curl"))
        .arg("--socket")
        .arg(socket)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}

/// Nothing may connect: argument, help and version handling never starts a job.
async fn assert_never_contacted(listener: &UnixListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "research-curl contacted the Research socket"
    );
}

#[tokio::test]
async fn curl_binary_explains_unsupported_options_without_contacting_research() {
    let (_root, socket, listener) = listener();
    for arguments in [
        &["-sS", "-D", "headers.txt", "https://example.org/"][..],
        &["-o", "page.html", "https://example.org/"],
        &["-H", "Authorization: Bearer secret", "https://example.org/"],
        &["https://example.org/", "https://example.net/?token=1"],
    ] {
        let result = run_curl(&socket, arguments).await;
        assert_eq!(result.status.code(), Some(2), "{arguments:?}");
        assert!(result.stdout.is_empty());
        let message = String::from_utf8(result.stderr).unwrap();
        assert!(message.starts_with("research-curl: "), "{message}");
        assert!(message.contains("GET-only"), "{message}");
        assert!(message.contains("not full curl"), "{message}");
        assert!(
            message.contains("research-curl -fsSL --max-time 25 https://example.com/ > page.html")
        );
        assert!(message.contains("response headers") && message.contains("research_fetch"));
        assert!(
            !message.contains("to pass") && !message.contains("-- -"),
            "{message}"
        );
        assert!(
            !message.contains("secret") && !message.contains("token"),
            "{message}"
        );
    }
    assert_never_contacted(&listener).await;
}

#[tokio::test]
async fn curl_binary_names_the_unsupported_option_and_answers_version_and_help_locally() {
    let (_root, socket, listener) = listener();
    let rejected = run_curl(&socket, &["-D", "headers.txt", "https://example.org/"]).await;
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unsupported option '-D'"));

    for flag in ["--version", "-V"] {
        let version = run_curl(&socket, &[flag]).await;
        assert!(version.status.success(), "{flag}");
        let text = String::from_utf8(version.stdout).unwrap();
        assert_eq!(
            text.lines().next().unwrap(),
            format!("research-curl {}", env!("CARGO_PKG_VERSION"))
        );
        if flag == "--version" {
            assert!(text.contains("not curl") && text.contains("Supported options"));
        }
    }
    let help = run_curl(&socket, &["--help"]).await;
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("not full curl") && text.contains("> page.html"));
    assert!(text.contains("--max-time"));
    assert_never_contacted(&listener).await;
}
