//! Real controller running as namespace-root, never host-root. Only synthetic
//! observations, exact runtime library roots and test binaries are projected.
use secure_research::egress::{EgressMode, EgressState, control_state};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

fn required(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("required test setting: {name}"))
}

fn main() {
    if std::env::args().any(|arg| arg == "--inside") {
        check();
        return;
    }
    let mut command = tokio::process::Command::new(required("RESEARCH_TEST_BWRAP"));
    command.env_clear().args([
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--dir",
        "/nix/store",
        "--dir",
        "/input",
        "--dir",
        "/output",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]);
    for root in std::fs::read_to_string(required("RESEARCH_TEST_CONTROL_CLOSURE"))
        .unwrap()
        .lines()
    {
        let path = Path::new(root);
        assert_eq!(path.parent(), Some(Path::new("/nix/store")));
        assert!(path.is_dir());
        command.arg("--ro-bind").arg(path).arg(path);
    }
    command
        .arg("--ro-bind")
        .arg(required("RESEARCH_TEST_CONTROL"))
        .arg("/controller")
        .arg("--ro-bind")
        .arg(std::env::current_exe().unwrap())
        .arg("/probe")
        .args(["--", "/probe", "--inside"])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let status = tokio::time::timeout(Duration::from_secs(30), command.status())
                .await
                .expect("controller fixture timed out")
                .expect("sandbox launch failed");
            assert!(status.success(), "controller fixture failed: {status}");
        });
}

fn controller() -> Command {
    let mut command = Command::new("/controller");
    command.args([
        "--input",
        "/input/vpn.json",
        "--output",
        "/output/state.json",
        "--drain-seconds",
        "1",
    ]);
    command
}

fn observe(epoch: Uuid, mode: EgressMode) {
    let state = EgressState {
        version: 1,
        generation: epoch,
        mode,
        valid_until: chrono::Utc::now().timestamp() + 10,
        region: None,
    };
    let mut file = tempfile::NamedTempFile::new_in("/input").unwrap();
    serde_json::to_writer(file.as_file_mut(), &state).unwrap();
    file.persist("/input/vpn.json").unwrap();
}

fn wait_state(predicate: impl Fn(EgressState) -> bool) -> EgressState {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(state) = control_state(Path::new("/output/state.json"))
            && predicate(state.clone())
        {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "controller state transition timed out"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn check() {
    use std::os::unix::fs::PermissionsExt;
    assert!(rustix::process::geteuid().is_root());
    assert!(!Path::new("/home").exists());
    assert!(!Path::new("/run/credentials").exists());
    let epoch = Uuid::new_v4();
    observe(epoch, EgressMode::Ready);
    let mut first = controller().spawn().unwrap();
    let initial = wait_state(|state| state.mode == EgressMode::Ready);
    // A valid root-owned lease must not be accepted through an ancestor that
    // lets another identity replace it. Exercise the actual reader as root in
    // this synthetic namespace, rather than failing on the final file's UID.
    std::fs::create_dir("/unsafe").unwrap();
    std::fs::copy("/output/state.json", "/unsafe/state.json").unwrap();
    assert!(control_state(Path::new("/unsafe/state.json")).is_ok());
    for mode in [0o777, 0o775] {
        std::fs::set_permissions("/unsafe", std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(control_state(Path::new("/unsafe/state.json")).is_err());
    }
    std::fs::set_permissions("/unsafe", std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(control_state(Path::new("/unsafe/state.json")).is_ok());
    std::os::unix::fs::symlink("/output", "/alias").unwrap();
    assert!(control_state(Path::new("/alias/state.json")).is_err());
    assert!(control_state(Path::new("/output/../output/state.json")).is_err());
    assert!(control_state(Path::new("output/state.json")).is_err());
    let competing = controller().output().unwrap();
    assert!(!competing.status.success());
    assert_eq!(
        competing.stderr,
        b"{\"schema\":\"secure-research-diagnostic/v1\",\"component\":\"egress_control\",\"event\":\"process_failed\",\"phase\":\"lifecycle\",\"count\":1,\"error_code\":\"capacity\"}\n"
    );
    assert!(competing.stdout.is_empty());
    assert_eq!(
        wait_state(|state| state.mode == EgressMode::Ready).generation,
        initial.generation
    );

    observe(epoch, EgressMode::Draining);
    let draining = wait_state(|state| state.mode == EgressMode::Draining);
    assert_eq!(draining.generation, initial.generation);
    wait_state(|state| state.mode == EgressMode::Offline);
    observe(epoch, EgressMode::Ready);
    let recovered = wait_state(|state| state.mode == EgressMode::Ready);
    assert_ne!(recovered.generation, initial.generation);

    let next_epoch = Uuid::new_v4();
    observe(next_epoch, EgressMode::Ready);
    let changed = wait_state(|state| {
        state.mode == EgressMode::Ready && state.generation != recovered.generation
    });
    std::fs::set_permissions("/input/vpn.json", std::fs::Permissions::from_mode(0o666)).unwrap();
    wait_state(|state| state.mode == EgressMode::Offline);
    observe(next_epoch, EgressMode::Ready);
    let restored = wait_state(|state| state.mode == EgressMode::Ready);
    assert_ne!(restored.generation, changed.generation);

    // A symlink to otherwise valid, root-owned proof is not proof itself.
    std::fs::rename("/input/vpn.json", "/input/saved.json").unwrap();
    std::os::unix::fs::symlink("/input/saved.json", "/input/vpn.json").unwrap();
    wait_state(|state| state.mode == EgressMode::Offline);
    observe(next_epoch, EgressMode::Ready);
    wait_state(|state| state.mode == EgressMode::Ready);

    rustix::process::kill_process(
        rustix::process::Pid::from_raw(first.id() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    assert!(first.wait().unwrap().success());
    assert_eq!(
        control_state(Path::new("/output/state.json")).unwrap().mode,
        EgressMode::Offline
    );

    let mut restarted = controller().spawn().unwrap();
    let fresh = wait_state(|state| state.mode == EgressMode::Ready);
    assert_ne!(fresh.generation, restored.generation);
    restarted.kill().unwrap();
    assert!(!restarted.wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(4);
    while control_state(Path::new("/output/state.json")).is_ok() {
        assert!(
            Instant::now() < deadline,
            "dead controller left a valid lease"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::set_permissions("/output", std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(!controller().output().unwrap().status.success());
    println!("controller isolation, generation, drain, locking, permissions and shutdown passed");
}
