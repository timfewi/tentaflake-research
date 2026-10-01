use clap::Parser;
use secure_research::egress_control::{lock_output, protected_parent, publish};
use secure_research::error::{ErrorCode, Result};
use secure_research::vpn_observer::{Observation, Observer};
use secure_research::{diagnostics, diagnostics::Component, diagnostics::Event};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    #[arg(long, default_value = "/sys")]
    sysfs: PathBuf,
    /// Optional pre-recorded NETLINK_ROUTE RTM_GETROUTE dump, used only by the
    /// synthetic namespace fixture. Omitted in deployment, where the observer
    /// performs a live netlink dump of every routing table.
    #[arg(long)]
    route_dump: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        diagnostics::emit_error(Component::VpnObserver, error);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if !rustix::process::geteuid().is_root() {
        return Err(ErrorCode::PermissionDenied);
    }
    if !valid_interface(&args.interface) {
        return Err(ErrorCode::InvalidRequest);
    }
    protected_parent(&args.output)?;
    // The observation directory is deliberately distinct from the controller's
    // control directory; this lock only excludes a second observer of the same
    // lease file. The controller keeps its own lock in its own directory.
    let _lock = lock_output(&args.output)?;
    let mut observer = Observer::new();
    // Fail closed before the first proof: never leave a predecessor's Ready lease.
    publish(
        &args.output,
        &observer.update(&not_ready(), chrono::Utc::now().timestamp()),
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
                &observer.update(&not_ready(), chrono::Utc::now().timestamp()),
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

fn not_ready() -> Observation {
    Observation {
        interface_up: false,
        default_route: false,
        firewall_marker: false,
        region: None,
    }
}

fn diagnostic(event: Event) {
    diagnostics::emit(Component::VpnObserver, event);
}

fn gather(args: &Args) -> Observation {
    Observation {
        interface_up: interface_up(&args.sysfs, &args.interface),
        default_route: default_route(&args.interface, args.route_dump.as_deref()),
        firewall_marker: firewall_marker(&args.firewall_marker),
        region: args.region.clone(),
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

/// A default IPv4 route on the named interface, searched across every routing
/// table. Tailscale's exit-node feature installs the default route in a
/// policy-routing table rather than the main table, so reading only
/// `/proc/net/route` would falsely report offline. A live NETLINK_ROUTE dump
/// covers all tables. IPv6 default-route proof stays delegated to the kernel
/// firewall invariant.
fn default_route(interface: &str, route_dump: Option<&Path>) -> bool {
    let index = match nix::net::if_::if_nametoindex(interface) {
        Ok(index) => index,
        Err(_) => {
            diagnostic(Event::InterfaceIndexUnavailable);
            return false;
        }
    };
    let dump = route_dump.map_or_else(read_route_dump, |path| std::fs::read(path).ok());
    let Some(dump) = dump else {
        diagnostic(Event::RouteDumpUnavailable);
        return false;
    };
    match default_route_index(&dump, index) {
        Some(true) => true,
        Some(false) => {
            diagnostic(Event::NoDefaultRoute);
            false
        }
        None => {
            diagnostic(Event::RouteDumpMalformed);
            false
        }
    }
}

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300; // NLM_F_ROOT | NLM_F_MATCH
const AF_INET: u8 = 2;
const RTA_OIF: u16 = 4;
const MAX_ROUTE_DUMP_BYTES: usize = 4 * 1024 * 1024;

fn align4(length: usize) -> usize {
    (length + 3) & !3
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// True once the dump has reached its terminating NLMSG_DONE. A not-yet-complete
/// prefix, or a truncated header, reads false so the caller keeps reading up to
/// the size bound and then fails closed.
fn dump_complete(dump: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 16 <= dump.len() {
        let length = u32_at(dump, offset) as usize;
        if length < 16 || offset + length > dump.len() {
            return false;
        }
        if u16_at(dump, offset + 4) == NLMSG_DONE {
            return true;
        }
        offset += align4(length);
    }
    false
}

/// The route's output interface index from its RTA_OIF attribute, if present.
fn route_output_index(payload: &[u8]) -> Option<u32> {
    // payload begins with a 12-byte rtmsg; attributes follow.
    if payload.len() < 12 {
        return None;
    }
    let mut offset = 12;
    while offset + 4 <= payload.len() {
        let length = u16_at(payload, offset) as usize;
        let attribute = u16_at(payload, offset + 2);
        if length < 4 || offset + length > payload.len() {
            return None;
        }
        if attribute == RTA_OIF && length >= 8 {
            return Some(u32_at(payload, offset + 4));
        }
        offset += align4(length);
    }
    None
}

/// Parse a NETLINK_ROUTE RTM_GETROUTE dump and report whether any IPv4 default
/// route leaves through `target_index`. `None` means the dump is truncated or
/// malformed and must be treated as not-ready.
fn default_route_index(dump: &[u8], target_index: u32) -> Option<bool> {
    let mut offset = 0;
    let mut found = false;
    while offset < dump.len() {
        if dump.len() - offset < 16 {
            return None;
        }
        let length = u32_at(dump, offset) as usize;
        if length < 16 || offset + length > dump.len() {
            return None;
        }
        let message_type = u16_at(dump, offset + 4);
        let payload = &dump[offset + 16..offset + length];
        match message_type {
            NLMSG_DONE => return Some(found),
            NLMSG_ERROR if payload.len() >= 4 && u32_at(payload, 0) != 0 => return None,
            RTM_NEWROUTE if payload.len() >= 12 => {
                let family = payload[0];
                let destination_length = payload[1];
                if family == AF_INET
                    && destination_length == 0
                    && route_output_index(payload) == Some(target_index)
                {
                    found = true;
                }
            }
            _ => {}
        }
        offset += align4(length);
    }
    None
}

fn route_dump_request() -> Vec<u8> {
    let mut request = vec![0u8; 28];
    request[0..4].copy_from_slice(&28u32.to_ne_bytes()); // nlmsg_len
    request[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    // rtmsg: family AF_INET, table RT_TABLE_UNSPEC (0) -> dump every table.
    request[16] = AF_INET;
    request
}

fn read_route_dump() -> Option<Vec<u8>> {
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
        &route_dump_request(),
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
        if dump_complete(&dump) {
            return Some(dump);
        }
        if dump.len() > MAX_ROUTE_DUMP_BYTES {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn done_message() -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&16u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        bytes
    }

    fn route_message(
        family: u8,
        destination_length: u8,
        table: u8,
        output_index: Option<u32>,
    ) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0] = family;
        payload[1] = destination_length;
        payload[4] = table;
        if let Some(index) = output_index {
            let mut attribute = vec![0u8; 8];
            attribute[0..2].copy_from_slice(&8u16.to_ne_bytes());
            attribute[2..4].copy_from_slice(&RTA_OIF.to_ne_bytes());
            attribute[4..8].copy_from_slice(&index.to_ne_bytes());
            payload.extend_from_slice(&attribute);
        }
        let length = 16 + payload.len();
        let mut bytes = vec![0u8; align4(length)];
        bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        bytes[16..16 + payload.len()].copy_from_slice(&payload);
        bytes
    }

    #[test]
    fn default_route_in_a_policy_routing_table_is_detected() {
        let mut dump = route_message(AF_INET, 0, 52, Some(7));
        dump.extend_from_slice(&done_message());
        assert_eq!(default_route_index(&dump, 7), Some(true));
    }

    #[test]
    fn default_route_in_the_main_table_still_matches() {
        let mut dump = route_message(AF_INET, 0, 254, Some(7));
        dump.extend_from_slice(&done_message());
        assert_eq!(default_route_index(&dump, 7), Some(true));
    }

    #[test]
    fn default_route_on_another_interface_is_ignored() {
        let mut dump = route_message(AF_INET, 0, 52, Some(3));
        dump.extend_from_slice(&done_message());
        assert_eq!(default_route_index(&dump, 7), Some(false));
    }

    #[test]
    fn a_non_default_route_does_not_satisfy_readiness() {
        let mut dump = route_message(AF_INET, 24, 52, Some(7));
        dump.extend_from_slice(&done_message());
        assert_eq!(default_route_index(&dump, 7), Some(false));
    }

    #[test]
    fn ipv6_default_route_is_not_counted() {
        let mut dump = route_message(10, 0, 52, Some(7));
        dump.extend_from_slice(&done_message());
        assert_eq!(default_route_index(&dump, 7), Some(false));
    }

    #[test]
    fn truncated_or_incomplete_dump_fails_closed() {
        let dump = route_message(AF_INET, 0, 52, Some(7));
        assert_eq!(default_route_index(&dump, 7), None);
        assert_eq!(default_route_index(&dump[..4], 7), None);
        assert!(!dump_complete(&dump));
    }

    #[test]
    fn netlink_error_fails_closed() {
        let mut bytes = vec![0u8; 20];
        bytes[0..4].copy_from_slice(&20u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1i32.to_ne_bytes()); // non-zero errno
        assert_eq!(default_route_index(&bytes, 7), None);
    }
}
