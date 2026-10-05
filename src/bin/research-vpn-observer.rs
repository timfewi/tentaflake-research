use clap::{Parser, ValueEnum};
use secure_research::egress_control::{lock_output, protected_parent, publish};
use secure_research::error::{ErrorCode, Result};
use secure_research::vpn_evidence::{
    self as evidence, AF_INET, AF_INET6, MAX_DUMP_BYTES, RTM_GETROUTE, RTM_GETRULE, Route, Rule,
};
use secure_research::vpn_observer::{Observation, Observer};
use secure_research::wireguard_evidence as wireguard;
use secure_research::{diagnostics, diagnostics::Component, diagnostics::Event};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// The tunnel implementation whose link kind is checked. Selecting one is an
/// operator decision; no vendor is required.
#[derive(Clone, Copy, ValueEnum)]
enum LinkKind {
    /// `DEVTYPE=wireguard` in the interface's uevent.
    Wireguard,
    /// A layer-3 tun device (for example Tailscale's), identified by `tun_flags`.
    Tun,
}

#[derive(Parser)]
struct Args {
    /// VPN interface whose IFF_UP flag and IPv4 default route are observed.
    #[arg(long)]
    interface: String,
    /// Root-owned observation lease consumed by research-egress-control.
    #[arg(long)]
    output: PathBuf,
    /// Renewal interval. The independent lease lifetime is ten seconds, so the
    /// cadence is capped at five seconds to retain renewal headroom.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=5))]
    refresh_seconds: u64,
    /// Operator-declared exit region (ISO 3166-1 alpha-2, uppercase). Never
    /// inferred; anything else fails closed to offline.
    #[arg(long)]
    region: Option<String>,
    /// Root-owned, non-group/world-writable file the operator's firewall
    /// installer creates. It is a marker, not proof of the firewall rules.
    #[arg(long)]
    firewall_marker: PathBuf,
    /// Require the interface to be this kind of link. Not selected by default.
    #[arg(long, value_enum)]
    link_kind: Option<LinkKind>,
    /// Observe the paths of this egress UID: unmarked IPv4 traffic must use the
    /// tunnel and IPv6 must not leave through another interface. Not selected by
    /// default; the baseline only needs a default route on the interface.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    egress_uid: Option<u32>,
    /// A resolver the egress identity queries (at most four). Each must be reached
    /// through the tunnel. Requires --egress-uid.
    #[arg(long = "dns-resolver", requires = "egress_uid", num_args = 1)]
    dns_resolvers: Vec<IpAddr>,
    /// Require the WireGuard peers to have completed a handshake within this many
    /// seconds, read from the kernel's WireGuard netlink dump (public keys and
    /// handshake times only; secrets in the dump are never kept). A session expires
    /// after 180 s and a keepalive tunnel re-handshakes about every two minutes, so
    /// use 180 or more. Requires `--link-kind wireguard`. Not selected by default.
    #[arg(long, value_parser = clap::value_parser!(u64).range(30..=3600))]
    handshake_within: Option<u64>,
    /// Pin the exit's identity: the interface's WireGuard peers must be exactly
    /// these base64 public keys (not secret; repeat for several, at most four).
    /// Requires `--link-kind wireguard`. Not selected by default.
    #[arg(long = "peer-public-key", value_parser = parse_public_key)]
    peer_public_keys: Vec<[u8; 32]>,
    /// Optional pre-recorded WireGuard netlink device dump, used only by the
    /// synthetic namespace fixture. Omitted in deployment, where the observer
    /// queries the kernel.
    #[arg(long)]
    wireguard_dump: Option<PathBuf>,
    /// A root-owned marker whose presence requests a planned exit change: the
    /// observer reports draining, and a fresh generation once it is removed.
    #[arg(long)]
    drain_marker: Option<PathBuf>,
    #[arg(long, default_value = "/sys")]
    sysfs: PathBuf,
    /// Optional pre-recorded NETLINK_ROUTE RTM_GETROUTE dump (IPv4 and, when
    /// observing an egress UID, IPv6 dumps concatenated), used only by the
    /// synthetic namespace fixture. Omitted in deployment, where the observer
    /// performs live netlink dumps of every routing table.
    #[arg(long)]
    route_dump: Option<PathBuf>,
    /// Optional pre-recorded RTM_GETRULE dump for the same fixture purpose.
    #[arg(long, requires = "egress_uid")]
    rule_dump: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::VpnObserver, error);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.dns_resolvers.len() > 4
        || args.peer_public_keys.len() > 4
        || (peer_evidence_selected(&args) && !matches!(args.link_kind, Some(LinkKind::Wireguard)))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    if !rustix::process::geteuid().is_root() {
        return Err(ErrorCode::PermissionDenied);
    }
    if !valid_interface(&args.interface) {
        return Err(ErrorCode::InvalidRequest);
    }
    protected_parent(&args.output)?;
    if let Some(marker) = &args.drain_marker {
        // A drain marker in a directory other identities can write is refused.
        protected_parent(marker)?;
    }
    // The observation directory is deliberately distinct from the controller's
    // control directory; this lock only excludes a second observer of the same
    // lease file. The controller keeps its own lock in its own directory.
    let _lock = lock_output(&args.output)?;
    let mut observer = Observer::new();
    // Fail closed before the first proof: never leave a predecessor's Ready lease.
    publish(
        &args.output,
        &observer.update(&Observation::not_ready(), chrono::Utc::now().timestamp()),
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ErrorCode::WorkerFailed)?
        .block_on(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|_| ErrorCode::WorkerFailed)?;
            let mut interval = tokio::time::interval(Duration::from_secs(args.refresh_seconds));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let observation = gather(&args);
                        let next = observer.update(
                            &observation,
                            chrono::Utc::now().timestamp(),
                        );
                        publish(&args.output, &next)?;
                    }
                    _ = term.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            publish(
                &args.output,
                &observer.update(&Observation::not_ready(), chrono::Utc::now().timestamp()),
            )
        })
}

/// The interface name becomes a path component, so restrict it to the same
/// character set the deployment module accepts. An operator typo must not read
/// or write outside the synthetic/host sysfs tree.
fn valid_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface != "."
        && interface != ".."
        && interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn diagnostic(event: Event) {
    diagnostics::emit(Component::VpnObserver, event);
}

fn gather(args: &Args) -> Observation {
    // An untrustworthy drain marker is never ignored: fail closed.
    let Some(draining) = drain_requested(args.drain_marker.as_deref()) else {
        return Observation::not_ready();
    };
    let index = match nix::net::if_::if_nametoindex(args.interface.as_str()) {
        Ok(index) => Some(index),
        Err(_) => {
            diagnostic(Event::InterfaceIndexUnavailable);
            None
        }
    };
    let routes = index.and_then(|_| read_routes(args));
    let default_route = match (&routes, index) {
        (Some(routes), Some(index)) => {
            let found = evidence::default_route_via(routes, AF_INET, index);
            if !found {
                diagnostic(Event::NoDefaultRoute);
            }
            found
        }
        _ => false,
    };
    let egress_paths = args.egress_uid.map(|uid| match (&routes, index) {
        (Some(routes), Some(index)) => egress_paths(args, routes, uid, index),
        _ => false,
    });
    Observation {
        interface_up: interface_up(&args.sysfs, &args.interface),
        default_route,
        firewall_marker: firewall_marker(&args.firewall_marker),
        region: args.region.clone(),
        link_kind: args
            .link_kind
            .map(|kind| link_kind(&args.sysfs, &args.interface, kind)),
        egress_paths,
        peers: peer_evidence_selected(args).then(|| peer_evidence(args)),
        draining,
    }
}

fn parse_public_key(text: &str) -> std::result::Result<[u8; 32], String> {
    wireguard::decode_public_key(text)
        .ok_or_else(|| "expected a base64 WireGuard public key".to_owned())
}

fn peer_evidence_selected(args: &Args) -> bool {
    args.handshake_within.is_some() || !args.peer_public_keys.is_empty()
}

/// The WireGuard peers' identity and recent handshakes. The kernel's dump also
/// carries the private key and preshared keys: only public keys and handshake
/// times are parsed, and every buffer that held the dump is scrubbed.
fn peer_evidence(args: &Args) -> bool {
    let Some(dump) = wireguard_dump(args) else {
        diagnostic(Event::PeerEvidenceUnavailable);
        return false;
    };
    let Some(peers) = wireguard::parse_peers(&dump) else {
        diagnostic(Event::PeerEvidenceMalformed);
        return false;
    };
    drop(dump);
    let now = chrono::Utc::now().timestamp();
    let pins = &args.peer_public_keys;
    let ok = wireguard::peers_ok(&peers, pins, args.handshake_within, now);
    if !ok {
        // Name the failed dimension without any key, address or time.
        if !pins.is_empty() && !wireguard::peers_ok(&peers, pins, None, now) {
            diagnostic(Event::PeerSetMismatch);
        } else {
            diagnostic(Event::HandshakeStale);
        }
    }
    ok
}

/// A recorded dump (synthetic fixture) or a live generic-netlink query.
fn wireguard_dump(args: &Args) -> Option<Zeroizing<Vec<u8>>> {
    match args.wireguard_dump.as_deref() {
        Some(path) => {
            use std::io::Read;
            let mut bytes = Zeroizing::new(Vec::with_capacity(wireguard::MAX_DUMP_BYTES));
            std::fs::File::open(path)
                .ok()?
                .take(wireguard::MAX_DUMP_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            (bytes.len() <= wireguard::MAX_DUMP_BYTES).then_some(bytes)
        }
        None => live_wireguard_dump(&args.interface),
    }
}

fn live_wireguard_dump(interface: &str) -> Option<Zeroizing<Vec<u8>>> {
    use nix::sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, recv, sendto,
        socket,
    };
    let socket = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkGeneric,
    )
    .ok()?;
    let send = |request: &[u8]| {
        sendto(
            socket.as_raw_fd(),
            request,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .ok()
    };
    send(&wireguard::family_request())?;
    let mut reply = [0u8; 1024];
    let received = recv(socket.as_raw_fd(), &mut reply, MsgFlags::empty()).ok()?;
    let family = wireguard::parse_family_id(&reply[..received])?;
    send(&wireguard::device_request(family, interface))?;
    // Preallocated so the buffer never reallocates, and scrubbed on drop.
    let mut dump = Zeroizing::new(Vec::with_capacity(wireguard::MAX_DUMP_BYTES));
    let mut buffer = Zeroizing::new([0u8; 16 * 1024]);
    loop {
        let received = recv(socket.as_raw_fd(), &mut buffer[..], MsgFlags::empty()).ok()?;
        if received == 0 || dump.len() + received > wireguard::MAX_DUMP_BYTES {
            return None;
        }
        dump.extend_from_slice(&buffer[..received]);
        if evidence::dump_complete(&dump) {
            return Some(dump);
        }
    }
}

fn interface_up(sysfs: &Path, interface: &str) -> bool {
    let path = sysfs.join("class/net").join(interface).join("flags");
    let Ok(content) = std::fs::read_to_string(&path) else {
        diagnostic(Event::InterfaceFlagsUnreadable);
        return false;
    };
    match u32::from_str_radix(content.trim().trim_start_matches("0x"), 16) {
        Ok(flags) => {
            let up = flags & 0x1 != 0;
            if !up {
                diagnostic(Event::InterfaceDown);
            }
            up
        }
        Err(_) => {
            diagnostic(Event::InterfaceFlagsMalformed);
            false
        }
    }
}

/// The interface is the selected kind of link, so a same-named dummy or bridge
/// device is not accepted as the tunnel.
fn link_kind(sysfs: &Path, interface: &str, kind: LinkKind) -> bool {
    let directory = sysfs.join("class/net").join(interface);
    let matches = match kind {
        LinkKind::Wireguard => match std::fs::read_to_string(directory.join("uevent")) {
            Ok(uevent) => uevent.lines().any(|line| line == "DEVTYPE=wireguard"),
            Err(_) => {
                diagnostic(Event::LinkKindUnreadable);
                return false;
            }
        },
        LinkKind::Tun => directory.join("tun_flags").is_file(),
    };
    if !matches {
        diagnostic(Event::LinkKindMismatch);
    }
    matches
}

/// `Some(false)` when no drain is requested, `Some(true)` for a trustworthy
/// marker and `None` for anything else, which the caller treats as offline.
fn drain_requested(marker: Option<&Path>) -> Option<bool> {
    let Some(path) = marker else {
        return Some(false);
    };
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0 =>
        {
            Some(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
        _ => {
            diagnostic(Event::DrainMarkerInsecure);
            None
        }
    }
}

/// Route evidence for every routing table: a live NETLINK_ROUTE dump, or the
/// synthetic fixture's recorded one. Tailscale's exit-node feature installs the
/// default route in a policy-routing table, which `/proc/net/route` would miss.
fn read_routes(args: &Args) -> Option<Vec<Route>> {
    let families: &[u8] = if args.egress_uid.is_some() {
        &[AF_INET, AF_INET6]
    } else {
        &[AF_INET]
    };
    let Some(dump) = dump(args.route_dump.as_deref(), RTM_GETROUTE, families) else {
        diagnostic(Event::RouteDumpUnavailable);
        return None;
    };
    let routes = evidence::parse_routes(&dump);
    if routes.is_none() {
        diagnostic(Event::RouteDumpMalformed);
    }
    routes
}

fn read_rules(args: &Args) -> Option<Vec<Rule>> {
    let Some(dump) = dump(args.rule_dump.as_deref(), RTM_GETRULE, &[AF_INET, AF_INET6]) else {
        diagnostic(Event::RuleDumpUnavailable);
        return None;
    };
    let rules = evidence::parse_rules(&dump);
    if rules.is_none() {
        diagnostic(Event::RuleDumpMalformed);
    }
    rules
}

/// IPv4 tunnel path, IPv6 containment and resolver paths of the egress UID.
fn egress_paths(args: &Args, routes: &[Route], uid: u32, tunnel_index: u32) -> bool {
    let Some(rules) = read_rules(args) else {
        return false;
    };
    let report = evidence::path_report(routes, &rules, uid, tunnel_index, &args.dns_resolvers);
    if !report.ipv4_tunnel {
        diagnostic(Event::Ipv4PathNotTunnel);
    }
    if !report.ipv6_contained {
        diagnostic(Event::Ipv6PathNotContained);
    }
    if !report.dns_tunnel {
        diagnostic(Event::DnsPathNotTunnel);
    }
    report.all()
}

const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300; // NLM_F_ROOT | NLM_F_MATCH

/// A recorded dump from the synthetic fixture, or live dumps of each family.
fn dump(recorded: Option<&Path>, kind: u16, families: &[u8]) -> Option<Vec<u8>> {
    match recorded {
        Some(path) => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take(MAX_DUMP_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            (bytes.len() <= MAX_DUMP_BYTES).then_some(bytes)
        }
        None => families
            .iter()
            .map(|family| read_dump(kind, *family))
            .collect::<Option<Vec<_>>>()
            .map(|dumps| dumps.concat()),
    }
}

fn dump_request(kind: u16, family: u8) -> Vec<u8> {
    let mut request = vec![0u8; 28];
    request[0..4].copy_from_slice(&28u32.to_ne_bytes()); // nlmsg_len
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    // rtmsg / fib_rule_hdr: the family selects the dump; table 0 is every table.
    request[16] = family;
    request
}

/// One live NETLINK_ROUTE dump (routes or rules) of a family, read to its
/// terminator within the size bound.
fn read_dump(kind: u16, family: u8) -> Option<Vec<u8>> {
    use nix::sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, recv, sendto,
        socket,
    };
    let socket = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )
    .ok()?;
    sendto(
        socket.as_raw_fd(),
        &dump_request(kind, family),
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )
    .ok()?;
    let mut dump = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let received = recv(socket.as_raw_fd(), &mut buffer, MsgFlags::empty()).ok()?;
        if received == 0 {
            return None;
        }
        dump.extend_from_slice(&buffer[..received]);
        if evidence::dump_complete(&dump) {
            return Some(dump);
        }
        if dump.len() > MAX_DUMP_BYTES {
            return None;
        }
    }
}

fn firewall_marker(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        diagnostic(Event::FirewallMarkerMissing);
        return false;
    };
    let secure = metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
    if !secure {
        diagnostic(Event::FirewallMarkerInsecure);
    }
    secure
}
