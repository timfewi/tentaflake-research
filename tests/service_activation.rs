//! Real systemd socket-activation launcher and research-service process. This is
//! FD/lifecycle evidence; the NixOS network and mount boundaries need their own VM.
use secure_research::{
    bridge::Bridge,
    budget::{JobState, Ledger},
    config::Config,
    protocol::Tool,
};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(check());
}

async fn check() {
    let launcher = std::env::var_os("RESEARCH_TEST_SOCKET_ACTIVATE")
        .map(PathBuf::from)
        .expect("set the pinned systemd-socket-activate executable");
    let binary = std::env::var_os("RESEARCH_TEST_SERVICE")
        .map(PathBuf::from)
        .expect("set the built research-service executable");
    let root = tempfile::tempdir().unwrap();
    let owner = rustix::process::getuid().as_raw();
    let config = Config {
        socket_path: root.path().join("research.sock"),
        state_directory: root.path().join("state"),
        egress_socket: root.path().join("unavailable-egress.sock"),
        egress_uid: Some(1002),
        egress_control_file: root.path().join("unavailable-control.json"),
        allowed_client_uids: vec![owner],
        ..Default::default()
    };
    let config_path = root.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    // The deployment provides a separate egress socket unit even while its VPN
    // controller is offline. No upstream connection is made in this fixture.
    let _egress = tokio::net::UnixListener::bind(&config.egress_socket).unwrap();
    std::fs::set_permissions(
        &config.egress_socket,
        std::fs::Permissions::from_mode(0o660),
    )
    .unwrap();
    let mut child = tokio::process::Command::new(&launcher)
        .arg("--listen")
        .arg(&config.socket_path)
        .arg(&binary)
        .arg("--listen-fd")
        .arg("3")
        .arg("--temporary-directory")
        .arg(root.path().join("temporary"))
        .arg("--public-only")
        .arg("--config")
        .arg(&config_path)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !config.socket_path.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "activation launcher exited before listening"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // The launcher has no SocketMode option. The real NixOS socket unit sets this
    // before activation; this local fixture sets it before its first connection.
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let bridge = match Bridge::connect(&config.socket_path).await {
        Ok(bridge) => bridge,
        Err(error) => {
            let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            panic!(
                "activated service connection failed ({error}): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
    let started = bridge
        .call(
            Tool::ResearchJob,
            json!({"operation":"start"}),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let job = serde_json::from_value(started["job"]["id"].clone()).unwrap();
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "research-service wrote to stdout");
    bridge.close().await;
    let ledger = Ledger::open(
        &config.state_directory.join("budget.sqlite"),
        config.limits.clone(),
    )
    .unwrap();
    assert!(matches!(
        ledger.get(owner, job).unwrap().state,
        JobState::Cancelled | JobState::Interrupted
    ));
    // No activation environment or the wrong inherited FD fails before serving.
    let output = tokio::process::Command::new(binary)
        .arg("--listen-fd")
        .arg("4")
        .arg("--temporary-directory")
        .arg(root.path().join("temporary"))
        .arg("--public-only")
        .arg("--config")
        .arg(config_path)
        .env_clear()
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"{\"schema\":\"secure-research-diagnostic/v1\",\"component\":\"service\",\"event\":\"process_failed\",\"phase\":\"lifecycle\",\"count\":1,\"error_code\":\"permission_denied\"}\n"
    );
}
