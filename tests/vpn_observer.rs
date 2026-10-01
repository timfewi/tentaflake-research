//! Real observer running as namespace-root, never host-root. Only synthetic
//! interface/route evidence, a synthetic marker and a test binary are projected;
//! no host VPN, firewall or route table is inspected.
use secure_research::egress::{EgressMode, EgressState, control_state};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
        .arg(required("RESEARCH_TEST_VPN_OBSERVER"))
        .arg("/observer")
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
                .expect("observer fixture timed out")
                .expect("sandbox launch failed");
            assert!(status.success(), "observer fixture failed: {status}");
        });
}

fn observer(region: &str) -> Command {
    let mut command = Command::new("/observer");
    command
        .args(["--interface", "lo"])
        .args(["--output", "/output/observation.json"])
        .args(["--refresh-seconds", "1"])
        .args(["--region", region])
        .args(["--firewall-marker", "/input/marker"])
        .args(["--sysfs", "/input/sys"])
        .args(["--route-dump", "/input/routes.dump"]);
    command
}

fn write_flags(sysfs: &Path, interface: &str, flags: u32) {
    let directory = sysfs.join("class/net").join(interface);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("flags"), format!("0x{flags:x}\n")).unwrap();
}

const RTM_NEWROUTE: u16 = 24;
const NLMSG_DONE: u16 = 3;
const AF_INET: u8 = 2;
const RTA_OIF: u16 = 4;

/// Write a synthetic NETLINK_ROUTE RTM_GETROUTE dump. When `default` is true the
/// default route leaves through the `lo` interface (ifindex 1 in a fresh
/// namespace) from policy-routing table 52, reproducing the Tailscale exit-node
/// layout that `/proc/net/route` (main table only) would miss. When false, the
/// default route leaves through a different interface.
fn write_route_dump(default: bool) {
    let mut payload = vec![0u8; 12];
    payload[0] = AF_INET;
    payload[1] = 0; // destination length 0 -> default route
    payload[4] = 52; // policy-routing table
    let output_index = if default { 1u32 } else { 2u32 };
    let mut attribute = vec![0u8; 8];
    attribute[0..2].copy_from_slice(&8u16.to_ne_bytes());
    attribute[2..4].copy_from_slice(&RTA_OIF.to_ne_bytes());
    attribute[4..8].copy_from_slice(&output_index.to_ne_bytes());
    payload.extend_from_slice(&attribute);
    let length = 16 + payload.len();
    let mut dump = vec![0u8; (length + 3) & !3];
    dump[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    dump[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
    dump[16..16 + payload.len()].copy_from_slice(&payload);
    let mut done = vec![0u8; 16];
    done[0..4].copy_from_slice(&16u32.to_ne_bytes());
    done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
    dump.extend_from_slice(&done);
    std::fs::write("/input/routes.dump", dump).unwrap();
}

fn wait_state(predicate: impl Fn(EgressState) -> bool) -> EgressState {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(state) = control_state(Path::new("/output/observation.json"))
            && predicate(state.clone())
        {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "observer state transition timed out"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn check() {
    use std::os::unix::fs::PermissionsExt;
    assert!(rustix::process::geteuid().is_root());
    assert!(!Path::new("/home").exists());
    let sysfs = Path::new("/input/sys");
    write_flags(sysfs, "lo", 0x1003);
    write_route_dump(true);
    let marker = Path::new("/input/marker");
    std::fs::write(marker, b"firewall\n").unwrap();
    std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut first = observer("DE").spawn().unwrap();
    let initial = wait_state(|state| state.mode == EgressMode::Ready);
    assert_eq!(initial.version, 1);
    assert_eq!(initial.region.as_deref(), Some("DE"));

    // A second observer cannot own the same observation directory.
    let competing = observer("DE").output().unwrap();
    assert!(!competing.status.success());
    assert_eq!(
        competing.stderr,
        b"{\"schema\":\"secure-research-diagnostic/v1\",\"component\":\"vpn_observer\",\"event\":\"process_failed\",\"phase\":\"lifecycle\",\"count\":1,\"error_code\":\"capacity\"}\n"
    );
    assert!(competing.stdout.is_empty());

    // Interface down is a failed check and drops to Offline.
    write_flags(sysfs, "lo", 0x1002);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_flags(sysfs, "lo", 0x1003);
    let recovered = wait_state(|state| state.mode == EgressMode::Ready);
    assert_ne!(recovered.generation, initial.generation);

    // A group/world-writable marker is not proof.
    std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o666)).unwrap();
    wait_state(|state| state.mode == EgressMode::Offline);
    std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    wait_state(|state| state.mode == EgressMode::Ready);

    // The interface must own the default IPv4 route, found in any routing table.
    write_route_dump(false);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_route_dump(true);
    wait_state(|state| state.mode == EgressMode::Ready);

    // SIGTERM publishes Offline before exit.
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(first.id() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    assert!(first.wait().unwrap().success());
    assert_eq!(
        control_state(Path::new("/output/observation.json"))
            .unwrap()
            .mode,
        EgressMode::Offline
    );

    // A restarted observer with a different declared region publishes it under a
    // fresh generation. The region is fixed per process, so this also exercises a
    // restart rather than a live region edit; the pure state machine covers the
    // region-change rotation directly.
    let mut restarted = observer("FR").spawn().unwrap();
    let rotated = wait_state(|state| state.mode == EgressMode::Ready);
    assert_eq!(rotated.region.as_deref(), Some("FR"));
    assert_ne!(rotated.generation, recovered.generation);
    restarted.kill().unwrap();
    assert!(!restarted.wait().unwrap().success());

    // An observation directory writable by other identities is not lockable.
    std::fs::set_permissions("/output", std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(!observer("DE").output().unwrap().status.success());
    println!("observer readiness, region, fail-closed checks, locking and shutdown passed");
}
