//! Real observer running as namespace-root, never host-root. Only synthetic
//! interface/route evidence, a synthetic marker and a test binary are projected;
//! no host VPN, firewall or route table is inspected.
use secure_research::egress::{EgressMode, EgressState, control_state};
use secure_research::vpn_evidence::{
    AF_INET, AF_INET6,
    synthetic::{RouteSpec, RuleSpec, dump, route, rule},
};
use secure_research::wireguard_evidence::synthetic::{device_dump, peer};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
            let status = tokio::time::timeout(Duration::from_secs(120), command.status())
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

/// Write a synthetic NETLINK_ROUTE RTM_GETROUTE dump. When `default` is true the
/// default route leaves through the `lo` interface (ifindex 1 in a fresh
/// namespace) from policy-routing table 52, reproducing the Tailscale exit-node
/// layout that `/proc/net/route` (main table only) would miss. When false, the
/// default route leaves through a different interface.
fn write_route_dump(default: bool) {
    let output_index = if default {
        TUNNEL_INDEX
    } else {
        PHYSICAL_INDEX
    };
    write_atomic(
        "/input/routes.dump",
        dump(&[route(&RouteSpec::default_route(AF_INET, 52, output_index))]),
    );
}

const TUNNEL_INDEX: u32 = 1; // `lo` in a fresh namespace stands in for the tunnel.
const PHYSICAL_INDEX: u32 = 2;

fn write_atomic(path: &str, bytes: Vec<u8>) {
    // The observer re-reads these every second; a half-written dump would be a
    // spurious Offline and rotate the generation under test.
    std::fs::write(format!("{path}.tmp"), bytes).unwrap();
    std::fs::rename(format!("{path}.tmp"), path).unwrap();
}

/// A `wg-quick`-style layout for both families: a tunnel table for unmarked
/// traffic, a suppressed main lookup and a direct main default. `v4_rule` and
/// `v6_rule` remove the family's tunnel rule (a direct-path leak) and `dns_leak`
/// routes the resolver's prefix through the physical link inside the tunnel table.
fn write_layout(v4_rule: bool, v6_rule: bool, dns_leak: bool) {
    let (mut routes, mut rules) = (Vec::new(), Vec::new());
    for (family, tunnel_rule) in [(AF_INET, v4_rule), (AF_INET6, v6_rule)] {
        let mut family_routes = vec![
            route(&RouteSpec::default_route(family, 51820, TUNNEL_INDEX)),
            route(&RouteSpec::default_route(family, 254, PHYSICAL_INDEX)),
        ];
        if dns_leak && family == AF_INET {
            family_routes.push(route(&RouteSpec::to(
                AF_INET,
                "9.9.9.0".parse().unwrap(),
                24,
                51820,
                PHYSICAL_INDEX,
            )));
        }
        routes.extend(dump(&family_routes));
        let mut family_rules = vec![
            RuleSpec::lookup(family, 0, 255),
            RuleSpec::lookup(family, 32766, 254),
            RuleSpec::lookup(family, 32767, 253),
            RuleSpec {
                suppress_prefix_len: Some(0),
                ..RuleSpec::lookup(family, 32764, 254)
            },
        ];
        if tunnel_rule {
            family_rules.push(RuleSpec {
                invert: true,
                mark: Some((0xca6c, u32::MAX)),
                ..RuleSpec::lookup(family, 32765, 51820)
            });
        }
        rules.extend(dump(&family_rules.iter().map(rule).collect::<Vec<_>>()));
    }
    write_atomic("/input/routes.dump", routes);
    write_atomic("/input/rules.dump", rules);
}

fn write_uevent(sysfs: &Path, interface: &str, devtype: &str) {
    let directory = sysfs.join("class/net").join(interface);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("uevent"),
        format!("DEVTYPE={devtype}\nINTERFACE={interface}\n"),
    )
    .unwrap();
}

const WIREGUARD_FAMILY: u16 = 33;
/// The pinned exit's public key (not a secret) and another peer's.
const EXIT_KEY: [u8; 32] = [7; 32];
const OTHER_KEY: [u8; 32] = [9; 32];

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A synthetic WireGuard device dump (which also carries private and preshared key
/// patterns the observer must never keep): the given peers, each with the age of
/// its last handshake in seconds.
fn write_peers(peers: &[([u8; 32], Option<i64>)]) {
    let now = unix_now();
    let elements: Vec<Vec<u8>> = peers
        .iter()
        .map(|(key, age)| peer(*key, age.map(|age| now - age)))
        .collect();
    write_atomic(
        "/input/wireguard.dump",
        device_dump(WIREGUARD_FAMILY, &elements),
    );
}

fn exit_key_text() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(EXIT_KEY)
}

fn selected_evidence_observer() -> Command {
    let mut command = observer("DE");
    command
        .args(["--link-kind", "wireguard", "--egress-uid", "2"])
        .args(["--handshake-within", "60"])
        .args(["--peer-public-key", &exit_key_text()])
        .args(["--wireguard-dump", "/input/wireguard.dump"])
        .args(["--dns-resolver", "9.9.9.9", "--dns-resolver", "2620:fe::fe"])
        .args(["--rule-dump", "/input/rules.dump"])
        .args(["--drain-marker", "/input/drain"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn terminate(child: &mut std::process::Child) {
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
}

/// Selected path evidence, link kind and planned draining with the real observer
/// over synthetic tunnel layouts; no host route, rule or interface is read.
fn selected_evidence_check() {
    use std::os::unix::fs::PermissionsExt;
    let sysfs = Path::new("/input/sys");
    write_flags(sysfs, "lo", 0x1003);
    write_uevent(sysfs, "lo", "wireguard");
    write_layout(true, true, false);
    let _ = std::fs::remove_file("/input/drain");
    write_peers(&[(EXIT_KEY, Some(5))]);
    let mut child = selected_evidence_observer().spawn().unwrap();
    // The previous (killed) observer's last Ready lease may still be on disk for
    // up to ten seconds; only this observer's own proof counts.
    let initial = wait_state(|state| {
        state.mode == EgressMode::Ready && state.region.as_deref() == Some("DE")
    });
    assert_ne!(initial.generation, Uuid::nil());

    // IPv4 direct path: without the unmarked-traffic rule the physical default wins.
    write_layout(false, true, false);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_layout(true, true, false);
    wait_state(|state| state.mode == EgressMode::Ready);
    // IPv6 direct path.
    write_layout(true, false, false);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_layout(true, true, false);
    wait_state(|state| state.mode == EgressMode::Ready);
    // DNS: the resolver's prefix is routed through the physical link.
    write_layout(true, true, true);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_layout(true, true, false);
    wait_state(|state| state.mode == EgressMode::Ready);
    // A handshake older than the window means the tunnel may be dead.
    write_peers(&[(EXIT_KEY, Some(120))]);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_peers(&[(EXIT_KEY, Some(5))]);
    wait_state(|state| state.mode == EgressMode::Ready);
    // A different peer, or an extra one, is not the pinned exit.
    write_peers(&[(OTHER_KEY, Some(5))]);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_peers(&[(EXIT_KEY, Some(5)), (OTHER_KEY, Some(5))]);
    wait_state(|state| state.mode == EgressMode::Offline);
    write_peers(&[(EXIT_KEY, Some(5))]);
    wait_state(|state| state.mode == EgressMode::Ready);
    // A dump the observer cannot read is not evidence.
    write_atomic("/input/wireguard.dump", b"junk".to_vec());
    wait_state(|state| state.mode == EgressMode::Offline);
    write_peers(&[(EXIT_KEY, Some(5))]);
    wait_state(|state| state.mode == EgressMode::Ready);
    // A device that merely has the interface's name is not a WireGuard tunnel.
    write_uevent(sysfs, "lo", "dummy");
    wait_state(|state| state.mode == EgressMode::Offline);
    write_uevent(sysfs, "lo", "wireguard");
    let epoch = wait_state(|state| state.mode == EgressMode::Ready);
    // A malformed rule dump is not evidence.
    write_atomic("/input/rules.dump", b"junk".to_vec());
    wait_state(|state| state.mode == EgressMode::Offline);
    write_layout(true, true, false);
    let epoch_before_drain = wait_state(|state| state.mode == EgressMode::Ready);
    assert_ne!(epoch_before_drain.generation, epoch.generation);

    // A planned exit change drains the old generation and then starts a new one.
    let marker = Path::new("/input/drain");
    std::fs::write(marker, b"drain\n").unwrap();
    std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    let draining = wait_state(|state| state.mode == EgressMode::Draining);
    assert_eq!(draining.generation, epoch_before_drain.generation);
    assert_eq!(draining.region.as_deref(), Some("DE"));
    std::fs::remove_file(marker).unwrap();
    let resumed = wait_state(|state| state.mode == EgressMode::Ready);
    assert_ne!(resumed.generation, epoch_before_drain.generation);
    // A marker other identities can write is never trusted: offline.
    std::fs::write(marker, b"drain\n").unwrap();
    std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o666)).unwrap();
    wait_state(|state| state.mode == EgressMode::Offline);
    std::fs::remove_file(marker).unwrap();
    wait_state(|state| state.mode == EgressMode::Ready);

    // Shutdown publishes Offline, and the diagnostics identify the failed evidence
    // without naming an address, interface, path or implementation.
    terminate(&mut child);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let diagnostics = String::from_utf8(output.stderr).unwrap();
    for event in [
        "ipv4_path_not_tunnel",
        "ipv6_path_not_contained",
        "dns_path_not_tunnel",
        "link_kind_mismatch",
        "handshake_stale",
        "peer_set_mismatch",
        "peer_evidence_malformed",
        "rule_dump_malformed",
        "drain_marker_insecure",
    ] {
        assert!(
            diagnostics.contains(&format!("\"event\":\"{event}\"")),
            "{event}"
        );
    }
    for secret in [
        "9.9.9.9",
        "2620",
        "/input",
        "wireguard",
        "dummy",
        "lo\"",
        &exit_key_text(),
    ] {
        assert!(!diagnostics.contains(secret), "diagnostics leaked {secret}");
    }
    assert!(diagnostics.lines().all(|line| line.len() < 256));
    assert_eq!(
        control_state(Path::new("/output/observation.json"))
            .unwrap()
            .mode,
        EgressMode::Offline
    );
}

#[track_caller]
fn wait_state(predicate: impl Fn(EgressState) -> bool) -> EgressState {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = None;
    loop {
        if let Ok(state) = control_state(Path::new("/output/observation.json")) {
            if predicate(state.clone()) {
                return state;
            }
            last = Some(state);
        }
        assert!(
            Instant::now() < deadline,
            "observer state transition timed out; last state {last:?}"
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

    selected_evidence_check();

    // An observation directory writable by other identities is not lockable.
    std::fs::set_permissions("/output", std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(!observer("DE").output().unwrap().status.success());
    println!(
        "observer readiness, selected path/link evidence, draining, fail-closed checks, locking and shutdown passed"
    );
}
