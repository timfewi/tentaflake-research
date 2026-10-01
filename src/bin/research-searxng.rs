//! Socket-activated local metasearch supervisor. Nix supplies a private network
//! namespace: the only upstream path is the authenticated Unix egress relay.
use clap::Parser;
use secure_research::{
    diagnostics::{self, Component},
    error::{ErrorCode, Result},
    http::ProxyRelay,
    socket,
};
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    net::{TcpStream, UnixListener},
    sync::Semaphore,
    task::JoinSet,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    executable: PathBuf,
    #[arg(long, default_value = "/run/agent-research-searxng/socket")]
    socket: PathBuf,
    #[arg(long, default_value = "/run/agent-research-egress/socket")]
    egress_socket: PathBuf,
    #[arg(long)]
    client_uid: u32,
}

fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::Service, error);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if !args.executable.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    let listener = socket::activated_listener(3, &args.socket)?;
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()
        .map_err(|_| ErrorCode::WorkerFailed)?.block_on(async move {
        let listener = UnixListener::from_std(listener).map_err(|_| ErrorCode::PermissionDenied)?;
        let relay = ProxyRelay::start(&args.egress_socket, 0, 16).await?;
        let directory = tempfile::tempdir().map_err(|_| ErrorCode::Storage)?;
        let settings = directory.path().join("settings.yml");
        let config = serde_json::json!({
            "use_default_settings": {"engines": {"keep_only": ["duckduckgo", "google", "brave", "bing"]}},
            "general": {"debug": false, "enable_metrics": false},
            "server": {"bind_address": "127.0.0.1", "port": 8888, "secret_key": uuid::Uuid::new_v4().to_string(), "limiter": false, "image_proxy": false},
            "search": {"formats": ["json"], "safe_search": 0},
            "outgoing": {"request_timeout": 10.0, "max_request_timeout": 15.0,
                "pool_connections": 16, "pool_maxsize": 16, "retries": 0,
                "proxies": {"all://": [relay.url()]}},
            "engines": [
                {"name":"duckduckgo", "disabled":false}, {"name":"google", "disabled":false},
                {"name":"brave", "disabled":false}, {"name":"bing", "disabled":false}
            ]
        });
        std::fs::write(&settings, serde_json::to_vec(&config).map_err(|_| ErrorCode::InvalidRequest)?)
            .map_err(|_| ErrorCode::Storage)?;
        let mut child = tokio::process::Command::new(&args.executable)
            .env_clear().env("SEARXNG_SETTINGS_PATH", &settings)
            .env("HOME", directory.path()).env("TMPDIR", directory.path())
            .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .kill_on_drop(true).spawn().map_err(|_| ErrorCode::WorkerFailed)?;
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| ErrorCode::WorkerFailed)?;
        let permits = Arc::new(Semaphore::new(16));
        let mut tasks = JoinSet::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = term.recv() => break Ok(()),
                _ = tokio::signal::ctrl_c() => break Ok(()),
                _ = child.wait() => break Err(ErrorCode::WorkerFailed),
                accepted = listener.accept() => {
                    let (mut stream, _) = match accepted { Ok(value) => value, Err(_) => break Err(ErrorCode::WorkerFailed) };
                    if socket::authorized_peer(&stream, &[args.client_uid]).is_err() { continue; }
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(Duration::from_secs(35), async {
                            // Flask may still be starting when socket activation
                            // delivers the first request. Wait only locally.
                            let mut upstream = tokio::time::timeout(Duration::from_secs(10), async {
                                loop {
                                    if let Ok(stream) = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, 8888)).await { break stream; }
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                }
                            }).await.map_err(std::io::Error::other)?;
                            tokio::io::copy_bidirectional(&mut stream, &mut upstream).await
                        }).await;
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => (),
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let _ = child.kill().await;
        let _ = child.wait().await;
        relay.close().await;
        result
    })
}
