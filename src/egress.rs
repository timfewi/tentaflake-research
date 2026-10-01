//! Internal, bounded HTTP proxy. Only this process has host networking. The host
//! module additionally restricts its UID to the VPN, including DNS packets.

use crate::config::EgressConfig;
use crate::diagnostics::{self, Component, Event};
use crate::error::{ErrorCode, Result};
use crate::policy::{
    PublicUrl, limited_referrer, public_addresses, validate_origin_header, validate_read_preflight,
};
use crate::socket::authorized_peer;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    net::{DnsError, NetError, runtime::TokioRuntimeProvider},
    proto::op::ResponseCode,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_HEADER: usize = 16 * 1024;
pub const MAX_LEASE_SECONDS: i64 = 10;

/// Fixed, privacy-safe lease read categories for process diagnostics. They
/// intentionally carry no path, state payload, region, or generation value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseReadError {
    Unavailable,
    Invalid,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    Ready,
    Draining,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressState {
    pub version: u32,
    pub generation: Uuid,
    pub mode: EgressMode,
    /// Short root-controller lease. A dead monitor must not leave Ready latched.
    pub valid_until: i64,
    /// Observed VPN exit region as ISO 3166-1 alpha-2, when the adapter can
    /// establish it. Absent is valid and means no region-aware adaptation.
    /// Missing on older leases and observations, which stay valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// A region is `None` or exactly two ASCII uppercase letters. Anything else is
/// malformed and makes the whole lease invalid, so a contradictory profile is
/// never selected from an unvalidated field.
fn valid_region(region: &Option<String>) -> bool {
    region.as_ref().is_none_or(|region| {
        region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase())
    })
}

impl EgressState {
    pub(crate) fn valid_at(&self, now: i64) -> bool {
        lease_validity(self, now).is_ok()
    }

    pub fn offline() -> Self {
        Self {
            version: 1,
            generation: Uuid::nil(),
            mode: EgressMode::Offline,
            valid_until: 0,
            region: None,
        }
    }
}

fn lease_validity(state: &EgressState, now: i64) -> std::result::Result<(), LeaseReadError> {
    if state.version != 1 || state.generation.is_nil() || !valid_region(&state.region) {
        return Err(LeaseReadError::Invalid);
    }
    if state.valid_until <= now {
        return Err(LeaseReadError::Expired);
    }
    if state.valid_until > now.saturating_add(MAX_LEASE_SECONDS) {
        return Err(LeaseReadError::Invalid);
    }
    Ok(())
}

pub fn control_state(path: &Path) -> Result<EgressState> {
    control_state_diagnostic(path).map_err(|_| ErrorCode::EgressUnavailable)
}

pub fn control_state_diagnostic(path: &Path) -> std::result::Result<EgressState, LeaseReadError> {
    // File ownership alone is insufficient: a writable or symlinked ancestor
    // can substitute root-owned proof. Use the controller's same trust policy
    // before opening the lease; only root may change any traversed directory.
    crate::egress_control::protected_parent(path).map_err(|_| LeaseReadError::Invalid)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| LeaseReadError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| LeaseReadError::Unavailable)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || !metadata.is_file()
        || metadata.len() > 4096
    {
        return Err(LeaseReadError::Invalid);
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 4097), &mut bytes)
        .map_err(|_| LeaseReadError::Unavailable)?;
    let state: EgressState = serde_json::from_slice(&bytes).map_err(|_| LeaseReadError::Invalid)?;
    let now = chrono::Utc::now().timestamp();
    lease_validity(&state, now)?;
    Ok(state)
}

pub struct PublicDns {
    resolver: TokioResolver,
}

impl PublicDns {
    pub fn new(resolvers: &[IpAddr]) -> Result<Self> {
        let mut config = ResolverConfig::default();
        config.name_servers = resolvers
            .iter()
            .copied()
            .map(NameServerConfig::udp_and_tcp)
            .collect();
        Self::with_config(config, Duration::from_secs(5))
    }

    fn with_config(config: ResolverConfig, timeout: Duration) -> Result<Self> {
        let mut options = ResolverOpts::default();
        options.use_hosts_file = ResolveHosts::Never;
        options.timeout = timeout;
        options.attempts = 1;
        options.cache_size = 0; // Recheck each new connection; pooled connections keep their pinned IP.
        options.num_concurrent_reqs = 1;
        // Keep every address visible to public_addresses; filtering private
        // records here could turn a mixed answer into an accepted public one.
        options.deny_answers.clear();
        Ok(Self {
            resolver: TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()
                .map_err(|_| ErrorCode::EgressUnavailable)?,
        })
    }

    pub async fn addresses(&self, url: &PublicUrl, denied: &[IpNet]) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = url.host().parse::<IpAddr>() {
            return public_addresses(vec![SocketAddr::new(ip, url.port())], denied);
        }
        let name = format!("{}.", url.host());
        // Do not use lookup_ip's combined strategy: it accepts a successful A
        // answer when AAAA timed out, hiding an unvalidated address family.
        let (v4, v6) = tokio::join!(
            self.resolver.ipv4_lookup(name.clone()),
            self.resolver.ipv6_lookup(name)
        );
        let mut addresses = Vec::new();
        match v4 {
            Ok(answer) => addresses.extend(
                answer
                    .answers()
                    .iter()
                    .filter_map(|record| record.data.ip_addr())
                    .map(|ip| SocketAddr::new(ip, url.port())),
            ),
            Err(error) if no_data(&error) => (),
            Err(_) => {
                diagnostics::emit(Component::Egress, Event::DnsIpv4Failed);
                return Err(ErrorCode::EgressUnavailable);
            }
        }
        match v6 {
            Ok(answer) => addresses.extend(
                answer
                    .answers()
                    .iter()
                    .filter_map(|record| record.data.ip_addr())
                    .map(|ip| SocketAddr::new(ip, url.port())),
            ),
            Err(error) if no_data(&error) => (),
            Err(_) => {
                diagnostics::emit(Component::Egress, Event::DnsIpv6Failed);
                return Err(ErrorCode::EgressUnavailable);
            }
        }
        public_addresses(addresses, denied)
    }
}

fn no_data(error: &NetError) -> bool {
    matches!(error, NetError::Dns(DnsError::NoRecordsFound(records))
        if records.response_code == ResponseCode::NoError)
}

fn host_denied(config: &EgressConfig) -> Result<Vec<IpNet>> {
    let mut denied = config.denied_networks.clone();
    let mut vpn_up = false;
    for interface in nix::ifaddrs::getifaddrs().map_err(|_| ErrorCode::EgressUnavailable)? {
        if interface.interface_name == config.vpn_interface
            && interface
                .flags
                .contains(nix::net::if_::InterfaceFlags::IFF_UP)
        {
            vpn_up = true;
        }
        if let Some(address) = interface.address {
            if let Some(v4) = address.as_sockaddr_in() {
                denied.push(IpNet::from(IpAddr::V4(v4.ip())));
            }
            if let Some(v6) = address.as_sockaddr_in6() {
                denied.push(IpNet::from(IpAddr::V6(v6.ip())));
            }
        }
    }
    if !vpn_up {
        return Err(ErrorCode::EgressUnavailable);
    }
    Ok(denied)
}

async fn connect_pinned(addresses: Vec<SocketAddr>, interface: &str) -> Result<TcpStream> {
    for address in addresses {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|_| ErrorCode::EgressUnavailable)?;
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(|_| ErrorCode::EgressUnavailable)?;
        if let Ok(Ok(stream)) = timeout(Duration::from_secs(5), socket.connect(address)).await {
            return Ok(stream);
        }
    }
    diagnostics::emit(Component::Egress, Event::UpstreamConnectFailed);
    Err(ErrorCode::EgressUnavailable)
}

#[derive(Debug)]
struct ProxyRequest {
    target: PublicUrl,
    forwarded: Option<Vec<u8>>,
    body_bytes: usize,
}

fn parse_header(bytes: &[u8]) -> Result<ProxyRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request
        .parse(bytes)
        .map_err(|_| ErrorCode::InvalidRequest)?
    {
        httparse::Status::Complete(n) if n == bytes.len() && request.version == Some(1) => (),
        _ => return Err(ErrorCode::InvalidRequest),
    }
    let target = request.path.ok_or(ErrorCode::InvalidRequest)?;
    let method = request.method.ok_or(ErrorCode::InvalidRequest)?;
    let mut seen = std::collections::HashSet::new();
    let mut body_bytes = None;
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        if !seen.insert(name.clone())
            || header.value.iter().any(|b| *b < 0x20 || *b == 0x7f)
            || matches!(
                name.as_str(),
                "transfer-encoding" | "upgrade" | "trailer" | "expect"
            )
        {
            return Err(ErrorCode::InvalidRequest);
        }
        if name == "content-length" {
            if header.value.is_empty() || !header.value.iter().all(u8::is_ascii_digit) {
                return Err(ErrorCode::InvalidRequest);
            }
            let length = std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(ErrorCode::InvalidRequest)?;
            if length > crate::browser::request::MAX_BODY {
                return Err(ErrorCode::SizeLimit);
            }
            body_bytes = Some(length);
        }
    }
    if (method != "POST" && body_bytes.unwrap_or(0) != 0)
        || (method == "POST" && body_bytes.is_none())
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let body_bytes = body_bytes.unwrap_or(0);
    if method == "CONNECT" {
        // CONNECT uses authority-form only, explicit 443, no path/userinfo.
        let authority: http::uri::Authority =
            target.parse().map_err(|_| ErrorCode::DestinationDenied)?;
        if authority.port_u16() != Some(443) || target.contains('@') {
            return Err(ErrorCode::DestinationDenied);
        }
        let target = PublicUrl::parse(&format!("https://{target}/"))?;
        return Ok(ProxyRequest {
            target,
            forwarded: None,
            body_bytes,
        });
    }
    if !matches!(method, "GET" | "HEAD" | "POST" | "OPTIONS") {
        return Err(ErrorCode::PolicyDenied);
    }
    if method == "OPTIONS" {
        let header = |name: &str| {
            request
                .headers
                .iter()
                .find(|field| field.name.eq_ignore_ascii_case(name))
                .and_then(|field| std::str::from_utf8(field.value).ok())
        };
        validate_read_preflight(
            header("origin"),
            header("access-control-request-method"),
            header("access-control-request-headers"),
        )?;
        if request.headers.iter().any(|field| {
            !matches!(
                field.name.to_ascii_lowercase().as_str(),
                "host"
                    | "connection"
                    | "content-length"
                    | "accept"
                    | "accept-encoding"
                    | "accept-language"
                    | "user-agent"
                    | "origin"
                    | "access-control-request-method"
                    | "access-control-request-headers"
            )
        }) {
            return Err(ErrorCode::PolicyDenied);
        }
    }
    let target = PublicUrl::parse(target)?;
    if target.url().scheme() != "http" || target.url().fragment().is_some() {
        return Err(ErrorCode::DestinationDenied);
    }
    let mut forwarded = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        &target.request_url()[url::Position::BeforePath..],
        &target.url()[url::Position::BeforeHost..url::Position::AfterPort]
    )
    .into_bytes();
    if method == "POST" {
        forwarded.extend_from_slice(format!("Content-Length: {body_bytes}\r\n").as_bytes());
    }
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        // Reapply the service's metadata policy at this independent network
        // boundary. CONNECT remains opaque to this plaintext request parser.
        if name == "referer" {
            let value = std::str::from_utf8(header.value).map_err(|_| ErrorCode::InvalidRequest)?;
            if let Some(value) = limited_referrer(value, &target)? {
                forwarded.extend_from_slice(b"Referer: ");
                forwarded.extend_from_slice(value.as_bytes());
                forwarded.extend_from_slice(b"\r\n");
            }
            continue;
        }
        if name == "origin" {
            let value = std::str::from_utf8(header.value).map_err(|_| ErrorCode::InvalidRequest)?;
            validate_origin_header(value)?;
        }
        // An explicit allowlist prevents credentials and hop-by-hop controls
        // leaking over plaintext HTTP or changing the proxy's framing.
        if matches!(
            name.as_str(),
            "accept"
                | "accept-encoding"
                | "accept-language"
                | "user-agent"
                | "range"
                | "content-type"
                | "origin"
        ) || (method == "OPTIONS"
            && matches!(
                name.as_str(),
                "access-control-request-method" | "access-control-request-headers"
            ))
        {
            forwarded.extend_from_slice(header.name.as_bytes());
            forwarded.extend_from_slice(b": ");
            forwarded.extend_from_slice(header.value);
            forwarded.extend_from_slice(b"\r\n");
        }
    }
    forwarded.extend_from_slice(b"\r\n");
    Ok(ProxyRequest {
        target,
        forwarded: Some(forwarded),
        body_bytes,
    })
}

/// One length-delimited request per plaintext connection. Do not forward any
/// prefix until its complete bounded body is available; leave pipelined bytes
/// unread. Operator read authorization belongs to the sole service peer.
async fn forward_plaintext(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    request: &[u8],
    body_bytes: usize,
    remaining: &AtomicU64,
) -> Result<()> {
    if body_bytes > crate::browser::request::MAX_BODY {
        return Err(ErrorCode::SizeLimit);
    }
    let total = request.len() as u64 + body_bytes as u64;
    remaining
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
            left.checked_sub(total)
        })
        .map_err(|_| ErrorCode::SizeLimit)?;
    let mut body = vec![0; body_bytes];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| ErrorCode::InvalidRequest)?;
    writer
        .write_all(request)
        .await
        .map_err(|_| ErrorCode::EgressUnavailable)?;
    writer
        .write_all(&body)
        .await
        .map_err(|_| ErrorCode::EgressUnavailable)?;
    Ok(())
}

async fn header(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    // Read exactly through CRLFCRLF so CONNECT's following TLS bytes never get
    // mistaken for proxy headers. The outer deadline bounds slow senders.
    let mut bytes = Vec::with_capacity(1024);
    while bytes.len() < MAX_HEADER {
        bytes.push(
            stream
                .read_u8()
                .await
                .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(ErrorCode::SizeLimit)
}

async fn copy_bounded(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    remaining: &AtomicU64,
) -> Result<()> {
    let mut buffer = [0; 16 * 1024];
    loop {
        let n = reader
            .read(&mut buffer)
            .await
            .map_err(|_| ErrorCode::EgressUnavailable)?;
        if n == 0 {
            writer
                .shutdown()
                .await
                .map_err(|_| ErrorCode::EgressUnavailable)?;
            return Ok(());
        }
        if remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(n as u64)
            })
            .is_err()
        {
            return Err(ErrorCode::SizeLimit);
        }
        writer
            .write_all(&buffer[..n])
            .await
            .map_err(|_| ErrorCode::EgressUnavailable)?;
    }
}

async fn proxy(
    mut stream: UnixStream,
    config: Arc<EgressConfig>,
    dns: Arc<PublicDns>,
    mut states: watch::Receiver<EgressState>,
) -> Result<()> {
    let initial = (*states.borrow()).clone();
    if initial.mode != EgressMode::Ready {
        return Err(ErrorCode::EgressUnavailable);
    }
    let work = async {
        let parsed = parse_header(&header(&mut stream).await?)?;
        let denied = host_denied(&config)?;
        let addresses = dns.addresses(&parsed.target, &denied).await?;
        let mut upstream = connect_pinned(addresses, &config.vpn_interface).await?;
        let bytes = AtomicU64::new(config.connection_bytes);
        if let Some(request) = parsed.forwarded {
            forward_plaintext(
                &mut stream,
                &mut upstream,
                &request,
                parsed.body_bytes,
                &bytes,
            )
            .await?;
            // One request per plaintext connection: never forward pipelined
            // requests with a different authority or attacker-supplied body.
            copy_bounded(&mut upstream, &mut stream, &bytes).await
        } else {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(|_| ErrorCode::Cancelled)?;
            let (mut local_read, mut local_write) = stream.split();
            let (mut remote_read, mut remote_write) = upstream.split();
            tokio::try_join!(
                copy_bounded(&mut local_read, &mut remote_write, &bytes),
                copy_bounded(&mut remote_read, &mut local_write, &bytes)
            )?;
            Ok(())
        }
    };
    let changed = async {
        loop {
            if states.changed().await.is_err() {
                break;
            }
            let state = (*states.borrow_and_update()).clone();
            if state.generation != initial.generation || state.mode == EgressMode::Offline {
                break;
            }
        }
    };
    tokio::select! {
        result = timeout(Duration::from_secs(config.connection_seconds), work) => result.unwrap_or(Err(ErrorCode::Timeout)),
        _ = changed => Err(ErrorCode::EgressChanged),
    }
}

pub async fn serve(
    listener: UnixListener,
    config: EgressConfig,
    stop: CancellationToken,
) -> Result<()> {
    config.validate()?;
    let config = Arc::new(config);
    let dns = Arc::new(PublicDns::new(&config.resolvers)?);
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let (states, receiver) = watch::channel(EgressState::offline());
    let mut poll = tokio::time::interval(Duration::from_millis(100));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut control_issue = None;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            _ = poll.tick() => {
                let state = match control_state_diagnostic(&config.control_file) {
                    Ok(state) => {
                        control_issue = None;
                        state
                    }
                    Err(issue) => {
                        if control_issue != Some(issue) {
                            diagnostics::emit(Component::Egress, control_event(issue));
                            control_issue = Some(issue);
                        }
                        EgressState::offline()
                    }
                };
                let state = if host_denied(&config).is_ok() { state } else { EgressState::offline() };
                if *states.borrow() != state { states.send_replace(state); }
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.map_err(|_| ErrorCode::EgressUnavailable)?;
                if authorized_peer(&stream, &config.allowed_peer_uids).is_err() {
                    diagnostics::emit(Component::Egress, Event::RelayPeerUnauthorized);
                    continue;
                }
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                if states.borrow().mode != EgressMode::Ready {
                    // Fixed metadata only. Never echo a URL, header, or DNS error.
                    let _ = timeout(Duration::from_millis(100), stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
                    continue;
                }
                let config = config.clone();
                let dns = dns.clone();
                let receiver = receiver.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = proxy(stream, config, dns, receiver).await {
                        let event = match error {
                            ErrorCode::Timeout => Event::TransportTimeout,
                            ErrorCode::EgressChanged => Event::GenerationChanged,
                            ErrorCode::EgressUnavailable => Event::TransportUnavailable,
                            ErrorCode::DestinationDenied | ErrorCode::PolicyDenied => Event::DestinationDenied,
                            ErrorCode::SizeLimit => Event::TransportSizeLimit,
                            _ => Event::RequestRejected,
                        };
                        diagnostics::emit(Component::Egress, event);
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => (),
        }
    }
    states.send_replace(EgressState::offline());
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn control_event(issue: LeaseReadError) -> Event {
    match issue {
        LeaseReadError::Unavailable => Event::ControlLeaseUnavailable,
        LeaseReadError::Invalid => Event::ControlLeaseInvalid,
        LeaseReadError::Expired => Event::ControlLeaseExpired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::RecordType;

    #[test]
    fn lease_diagnostics_distinguish_expiry_from_invalid_shape() {
        let valid = EgressState {
            version: 1,
            generation: Uuid::new_v4(),
            mode: EgressMode::Ready,
            valid_until: 110,
            region: Some("DE".to_owned()),
        };
        assert_eq!(lease_validity(&valid, 100), Ok(()));
        assert_eq!(
            lease_validity(
                &EgressState {
                    valid_until: 100,
                    ..valid.clone()
                },
                100
            ),
            Err(LeaseReadError::Expired)
        );
        assert_eq!(
            lease_validity(
                &EgressState {
                    valid_until: 111,
                    ..valid.clone()
                },
                100
            ),
            Err(LeaseReadError::Invalid)
        );
        assert_eq!(
            lease_validity(
                &EgressState {
                    generation: Uuid::nil(),
                    ..valid
                },
                100
            ),
            Err(LeaseReadError::Invalid)
        );
    }

    #[test]
    fn proxy_rejects_private_authorities_and_ambiguous_framing() {
        for request in [
            "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:22 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:443/path HTTP/1.1\r\n\r\n",
            "CONNECT user@example.com:443 HTTP/1.1\r\n\r\n",
            "GET http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET http://example.com/ HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            "GET http://example.com/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: +2\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 65537\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
            "CONNECT example.com:443 HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ] {
            assert!(parse_header(request.as_bytes()).is_err(), "{request}");
        }
    }

    #[test]
    fn plaintext_credentials_and_hop_headers_never_reach_target() {
        let request = parse_header(b"GET http://example.com/page?a=1&b=2 HTTP/1.1\r\nHost: evil.test\r\nAuthorization: secret\r\nCookie: secret\r\nProxy-Authorization: secret\r\nConnection: keep-alive\r\nUser-Agent: PublicResearch/0.1\r\n\r\n").unwrap();
        let forwarded = String::from_utf8(request.forwarded.unwrap()).unwrap();
        assert!(forwarded.starts_with("GET /page?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(forwarded.contains("Connection: close"));
        assert!(!forwarded.contains("secret") && !forwarded.contains("evil.test"));
        assert!(
            parse_header(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                .unwrap()
                .forwarded
                .is_none()
        );
    }

    #[test]
    fn cache_validators_are_stripped_from_plaintext_proxy() {
        let request = parse_header(b"GET http://example.com/page HTTP/1.1\r\nIf-None-Match: \"session-tag\"\r\nIf-Modified-Since: Tue, 01 Jan 2030 00:00:00 GMT\r\nRange: bytes=0-9\r\n\r\n").unwrap();
        let forwarded = String::from_utf8(request.forwarded.unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert!(!forwarded.contains("if-none-match:"));
        assert!(!forwarded.contains("if-modified-since:"));
        assert!(forwarded.contains("range: bytes=0-9"));
    }

    #[test]
    fn plaintext_proxy_applies_referrer_and_origin_privacy_floor() {
        let request = parse_header(b"GET http://target.example/page HTTP/1.1\r\nReferer: http://source.example/private?token=secret#fragment\r\nOrigin: http://source.example\r\n\r\n").unwrap();
        let forwarded = String::from_utf8(request.forwarded.unwrap()).unwrap();
        assert!(forwarded.contains("Referer: http://source.example/\r\n"));
        assert!(!forwarded.contains("private?token=secret"));
        assert!(forwarded.contains("Origin: http://source.example\r\n"));

        let request = parse_header(b"GET http://target.example/page HTTP/1.1\r\nReferer: https://source.example/private?token=secret\r\n\r\n").unwrap();
        let forwarded = String::from_utf8(request.forwarded.unwrap()).unwrap();
        assert!(!forwarded.contains("Referer:"));

        let request = parse_header(b"GET http://target.example/page HTTP/1.1\r\nReferer: http://target.example/previous?view=one#fragment\r\nOrigin: null\r\n\r\n").unwrap();
        let forwarded = String::from_utf8(request.forwarded.unwrap()).unwrap();
        assert!(forwarded.contains("Referer: http://target.example/previous?view=one\r\n"));
        assert!(forwarded.contains("Origin: null\r\n"));

        assert!(parse_header(b"GET http://target.example/page HTTP/1.1\r\nOrigin: http://source.example/private?token=secret\r\n\r\n").is_err());
        assert!(parse_header(b"GET http://target.example/page HTTP/1.1\r\nReferer: http://127.0.0.1/private\r\n\r\n").is_err());
    }

    #[test]
    fn plaintext_preflight_forwards_only_a_credential_free_read_probe() {
        let request = parse_header(b"OPTIONS http://target.example/read HTTP/1.1\r\nOrigin: http://source.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\n\r\n").unwrap();
        let forwarded = String::from_utf8(request.forwarded.unwrap()).unwrap();
        assert!(forwarded.starts_with("OPTIONS /read HTTP/1.1\r\nHost: target.example\r\n"));
        assert!(forwarded.contains("Access-Control-Request-Method: POST\r\n"));
        assert!(forwarded.contains("Access-Control-Request-Headers: content-type\r\n"));
        for extra in [
            "Cookie: session=private\r\n",
            "Authorization: secret\r\n",
            "Range: bytes=0-1\r\n",
            "Access-Control-Request-Headers: authorization\r\n",
            "Access-Control-Request-Private-Network: true\r\n",
        ] {
            let request = format!(
                "OPTIONS http://target.example/read HTTP/1.1\r\nOrigin: http://source.example\r\nAccess-Control-Request-Method: POST\r\n{extra}\r\n"
            );
            assert!(parse_header(request.as_bytes()).is_err(), "{extra}");
        }
        assert!(parse_header(b"OPTIONS http://target.example/read HTTP/1.1\r\nOrigin: http://source.example\r\nAccess-Control-Request-Method: GET\r\n\r\n").is_err());
        assert!(parse_header(b"OPTIONS http://target.example/read HTTP/1.1\r\nAccess-Control-Request-Method: POST\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn tunnel_prebuffer_is_not_consumed_as_header() {
        let mut input = &b"CONNECT example.com:443 HTTP/1.1\r\n\r\nTLS-BYTES"[..];
        let bytes = header(&mut input).await.unwrap();
        assert!(parse_header(&bytes).is_ok());
        assert_eq!(input, b"TLS-BYTES");
    }

    #[tokio::test]
    async fn plaintext_post_forwards_exact_body_without_pipelined_authority() {
        let mut input = &b"POST http://example.com/read HTTP/1.1\r\nContent-Length: 2\r\nContent-Type: application/json\r\nCookie: secret\r\n\r\n{}GET http://127.0.0.1/ HTTP/1.1\r\n\r\n"[..];
        let parsed = parse_header(&header(&mut input).await.unwrap()).unwrap();
        assert_eq!(parsed.body_bytes, 2);
        let request = parsed.forwarded.unwrap();
        let budget = AtomicU64::new(1024);
        let mut upstream = Vec::new();
        forward_plaintext(
            &mut input,
            &mut upstream,
            &request,
            parsed.body_bytes,
            &budget,
        )
        .await
        .unwrap();
        assert_eq!(upstream, b"POST /read HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}");
        assert!(input.starts_with(b"GET http://127.0.0.1/"));
        assert_eq!(budget.load(Ordering::Acquire), 1024 - upstream.len() as u64);
    }

    #[tokio::test]
    async fn incomplete_or_over_budget_post_never_forwards_a_prefix() {
        for (input, budget, expected) in [
            (b"{".as_slice(), 1024, ErrorCode::InvalidRequest),
            (b"{}".as_slice(), 1, ErrorCode::SizeLimit),
        ] {
            let mut upstream = Vec::new();
            assert_eq!(
                forward_plaintext(
                    &mut &input[..],
                    &mut upstream,
                    b"header",
                    2,
                    &AtomicU64::new(budget)
                )
                .await,
                Err(expected)
            );
            assert!(upstream.is_empty());
        }
    }

    #[tokio::test]
    async fn byte_cap_stops_forwarding_before_excess() {
        let remaining = AtomicU64::new(4);
        let mut output = Vec::new();
        assert_eq!(
            copy_bounded(&mut &b"12345"[..], &mut output, &remaining).await,
            Err(ErrorCode::SizeLimit)
        );
        assert!(output.is_empty());
        copy_bounded(&mut &b"1234"[..], &mut output, &remaining)
            .await
            .unwrap();
        assert_eq!(output, b"1234");
        assert_eq!(remaining.load(Ordering::Acquire), 0);
    }

    async fn dns_fixture(
        answers: Vec<IpAddr>,
        failure: Option<(RecordType, Option<ResponseCode>)>,
    ) -> (PublicDns, tokio::task::JoinHandle<()>) {
        use hickory_resolver::proto::{
            op::{Message, OpCode},
            rr::{
                RData, Record, RecordType,
                rdata::{A, AAAA},
            },
        };
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            loop {
                let (size, sender) = socket.recv_from(&mut bytes).await.unwrap();
                let query = Message::from_vec(&bytes[..size]).unwrap();
                assert_eq!(query.queries.len(), 1);
                let question = query.queries[0].clone();
                assert!(matches!(
                    question.query_type(),
                    RecordType::A | RecordType::AAAA
                ));
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.recursion_desired = true;
                response.metadata.recursion_available = true;
                response.add_query(question.clone());
                if let Some((family, code)) = failure
                    && question.query_type() == family
                {
                    // No response models a DNS timeout for this family.
                    let Some(code) = code else { continue };
                    response.metadata.response_code = code;
                } else {
                    for address in &answers {
                        let data = match address {
                            IpAddr::V4(ip) if question.query_type() == RecordType::A => {
                                Some(RData::A(A(*ip)))
                            }
                            IpAddr::V6(ip) if question.query_type() == RecordType::AAAA => {
                                Some(RData::AAAA(AAAA(*ip)))
                            }
                            _ => None,
                        };
                        if let Some(data) = data {
                            response.add_answer(Record::from_rdata(
                                question.name().clone(),
                                60,
                                data,
                            ));
                        }
                    }
                }
                socket
                    .send_to(&response.to_vec().unwrap(), sender)
                    .await
                    .unwrap();
            }
        });
        // Test-only resolver endpoint. Production construction only receives
        // public addresses validated by EgressConfig, always on port 53.
        let mut config = ResolverConfig::default();
        let mut server_config = NameServerConfig::udp(address.ip());
        server_config.connections[0].port = address.port();
        config.name_servers.push(server_config);
        let dns = PublicDns::with_config(config, Duration::from_millis(200)).unwrap();
        (dns, server)
    }

    #[tokio::test]
    async fn real_dns_mixed_families_are_rejected_as_one_answer_set() {
        let (dns, server) = dns_fixture(
            vec!["8.8.8.8".parse().unwrap(), "fd00::1".parse().unwrap()],
            None,
        )
        .await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await,
            Err(ErrorCode::DestinationDenied)
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn successful_a_record_cannot_hide_aaaa_failure() {
        let (dns, server) = dns_fixture(
            vec!["8.8.8.8".parse().unwrap()],
            Some((RecordType::AAAA, Some(ResponseCode::ServFail))),
        )
        .await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await,
            Err(ErrorCode::EgressUnavailable)
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn successful_empty_family_is_distinct_from_dns_failure() {
        let (dns, server) = dns_fixture(vec!["8.8.8.8".parse().unwrap()], None).await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await
                .unwrap(),
            vec!["8.8.8.8:443".parse().unwrap()]
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn successful_aaaa_record_cannot_hide_a_failure() {
        let (dns, server) = dns_fixture(
            vec!["2001:4860:4860::8888".parse().unwrap()],
            Some((RecordType::A, Some(ResponseCode::ServFail))),
        )
        .await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await,
            Err(ErrorCode::EgressUnavailable)
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn successful_family_cannot_hide_timeout_or_nxdomain() {
        for family in [RecordType::A, RecordType::AAAA] {
            for code in [None, Some(ResponseCode::NXDomain)] {
                let (dns, server) = dns_fixture(
                    vec![
                        "8.8.8.8".parse().unwrap(),
                        "2001:4860:4860::8888".parse().unwrap(),
                    ],
                    Some((family, code)),
                )
                .await;
                assert_eq!(
                    dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                        .await,
                    Err(ErrorCode::EgressUnavailable),
                    "{family:?} {code:?}"
                );
                server.abort();
                let _ = server.await;
            }
        }
    }

    #[tokio::test]
    async fn real_dns_mixed_addresses_within_either_family_are_rejected() {
        for answers in [
            vec!["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()],
            vec![
                "2001:4860:4860::8888".parse().unwrap(),
                "fd00::1".parse().unwrap(),
            ],
        ] {
            let (dns, server) = dns_fixture(answers, None).await;
            assert_eq!(
                dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                    .await,
                Err(ErrorCode::DestinationDenied)
            );
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn real_dns_preserves_public_addresses_from_both_families() {
        let (dns, server) = dns_fixture(
            vec![
                "8.8.8.8".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ],
            None,
        )
        .await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await
                .unwrap(),
            vec![
                "8.8.8.8:443".parse().unwrap(),
                "1.1.1.1:443".parse().unwrap(),
                "[2001:4860:4860::8888]:443".parse().unwrap()
            ]
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn real_dns_empty_a_family_allows_public_aaaa() {
        let (dns, server) = dns_fixture(vec!["2001:4860:4860::8888".parse().unwrap()], None).await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await
                .unwrap(),
            vec!["[2001:4860:4860::8888]:443".parse().unwrap()]
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn real_dns_empty_answers_are_denied() {
        let (dns, server) = dns_fixture(vec![], None).await;
        assert_eq!(
            dns.addresses(&PublicUrl::parse("https://example.com/").unwrap(), &[])
                .await,
            Err(ErrorCode::DestinationDenied)
        );
        server.abort();
        let _ = server.await;
    }
}
