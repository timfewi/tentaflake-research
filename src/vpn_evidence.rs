//! Pure routing evidence for the reference VPN observer: parsing of
//! NETLINK_ROUTE route and rule dumps, and a conservative evaluation of where
//! the egress identity's unmarked packets would leave. Nothing here performs I/O,
//! runs a command or reads VPN credentials.
//!
//! The evaluation follows the kernel's policy-routing order (rules by priority,
//! first table with a matching route wins). Selectors it cannot decide for a
//! generic public destination make a rule *possibly* matching, and every possible
//! outcome is collected, so an unprovable layout is never reported as contained.

use std::net::IpAddr;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_GETRULE: u16 = 34;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;

const FRA_IIFNAME: u16 = 3;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_FLOW: u16 = 11;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_PAD: u16 = 18;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;

const RTN_UNICAST: u8 = 1;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;

const FR_ACT_TO_TBL: u8 = 1;
const FR_ACT_NOP: u8 = 3;
const FR_ACT_BLACKHOLE: u8 = 6;
const FR_ACT_UNREACHABLE: u8 = 7;
const FR_ACT_PROHIBIT: u8 = 8;
const FIB_RULE_INVERT: u32 = 0x2;

pub const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Unicast,
    /// Blackhole, unreachable or prohibit: packets are dropped or rejected.
    Blocked,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub family: u8,
    pub prefix_len: u8,
    pub destination: Option<IpAddr>,
    pub table: u32,
    pub kind: RouteKind,
    /// Only a plain RTA_OIF counts. A multipath or nexthop-object route has none,
    /// so it can never be proven to use the tunnel.
    pub output_index: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    ToTable,
    Blocked,
    Nop,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub family: u8,
    pub priority: u32,
    pub action: RuleAction,
    pub table: u32,
    pub invert: bool,
    pub uid_range: Option<(u32, u32)>,
    /// `(value, mask)` of an fwmark selector.
    pub mark: Option<(u32, u32)>,
    pub input_interface: Option<String>,
    /// Selectors a generic public destination cannot decide (addresses, TOS,
    /// ports, protocol, an output interface, VRF or any unknown attribute).
    pub undecidable: bool,
    pub suppress_prefix_len: Option<u32>,
}

pub(crate) fn align4(length: usize) -> usize {
    (length + 3) & !3
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// True once the dump has reached its terminating NLMSG_DONE or an NLMSG_ERROR,
/// which also ends a dump (the parser then rejects a failing one). A
/// not-yet-complete prefix, or a truncated header, reads false so the caller keeps
/// reading up to the size bound and then fails closed.
pub fn dump_complete(dump: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 16 <= dump.len() {
        let Some(length) = read_u32(dump, offset).map(|length| length as usize) else {
            return false;
        };
        if length < 16 || offset + length > dump.len() {
            return false;
        }
        if matches!(read_u16(dump, offset + 4), Some(NLMSG_DONE | NLMSG_ERROR)) {
            return true;
        }
        offset += align4(length);
    }
    false
}

pub(crate) struct Message<'a> {
    pub(crate) kind: u16,
    pub(crate) payload: &'a [u8],
}

/// Split one or several concatenated dumps into messages. Every dump must end
/// with NLMSG_DONE; a truncated, unterminated or error-carrying dump is `None`.
fn messages(dump: &[u8]) -> Option<Vec<Message<'_>>> {
    collect(dump, true)
}

/// Like [`messages`]; a single reply to a non-dump request has no NLMSG_DONE, so
/// `require_done` is false for it.
pub(crate) fn collect(dump: &[u8], require_done: bool) -> Option<Vec<Message<'_>>> {
    let mut offset = 0;
    let mut complete = !require_done;
    let mut found = Vec::new();
    while offset < dump.len() {
        let length = read_u32(dump, offset)? as usize;
        if length < 16 || offset.checked_add(length)? > dump.len() {
            return None;
        }
        let kind = read_u16(dump, offset + 4)?;
        let payload = &dump[offset + 16..offset + length];
        match kind {
            NLMSG_DONE => complete = true,
            NLMSG_ERROR => {
                if read_u32(payload, 0)? != 0 {
                    return None;
                }
            }
            _ => {
                complete = !require_done;
                found.push(Message { kind, payload });
            }
        }
        offset += align4(length);
    }
    complete.then_some(found)
}

/// Netlink attributes following a fixed `header`-byte message header (12 for a
/// route or rule, 4 for generic netlink, 0 for a nested list), or `None` when
/// malformed.
pub(crate) fn attributes(payload: &[u8], header: usize) -> Option<Vec<(u16, &[u8])>> {
    let mut offset = header;
    let mut found = Vec::new();
    while offset + 4 <= payload.len() {
        let length = read_u16(payload, offset)? as usize;
        // The nested/byte-order flag bits are not part of the type.
        let kind = read_u16(payload, offset + 2)? & 0x3fff;
        if length < 4 || offset + length > payload.len() {
            return None;
        }
        found.push((kind, &payload[offset + 4..offset + length]));
        offset += align4(length);
    }
    Some(found)
}

fn attribute_u32(value: &[u8]) -> Option<u32> {
    read_u32(value, 0).filter(|_| value.len() == 4)
}

fn address(value: &[u8], family: u8) -> Option<IpAddr> {
    match (family, value.len()) {
        (AF_INET, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(value).ok()?)),
        (AF_INET6, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(value).ok()?)),
        _ => None,
    }
}

/// Every route of every table and family in the dump.
pub fn parse_routes(dump: &[u8]) -> Option<Vec<Route>> {
    let mut routes = Vec::new();
    for message in messages(dump)? {
        if message.kind != RTM_NEWROUTE || message.payload.len() < 12 {
            continue;
        }
        let payload = message.payload;
        let family = payload[0];
        let kind = match payload[7] {
            RTN_UNICAST => RouteKind::Unicast,
            RTN_BLACKHOLE | RTN_UNREACHABLE | RTN_PROHIBIT => RouteKind::Blocked,
            _ => RouteKind::Other,
        };
        let mut route = Route {
            family,
            prefix_len: payload[1],
            destination: None,
            table: u32::from(payload[4]),
            kind,
            output_index: None,
        };
        for (attribute, value) in attributes(payload, 12)? {
            match attribute {
                RTA_DST => route.destination = Some(address(value, family)?),
                RTA_OIF => route.output_index = Some(attribute_u32(value)?),
                RTA_TABLE => route.table = attribute_u32(value)?,
                _ => {}
            }
        }
        routes.push(route);
    }
    Some(routes)
}

fn interface_name(value: &[u8]) -> Option<String> {
    let name = value.split(|byte| *byte == 0).next()?;
    std::str::from_utf8(name).ok().map(str::to_owned)
}

/// Every policy-routing rule of every family in the dump.
pub fn parse_rules(dump: &[u8]) -> Option<Vec<Rule>> {
    let mut rules = Vec::new();
    for message in messages(dump)? {
        if message.kind != RTM_NEWRULE || message.payload.len() < 12 {
            continue;
        }
        let payload = message.payload;
        let flags = read_u32(payload, 8)?;
        let mut rule = Rule {
            family: payload[0],
            priority: 0,
            action: match payload[7] {
                FR_ACT_TO_TBL => RuleAction::ToTable,
                FR_ACT_BLACKHOLE | FR_ACT_UNREACHABLE | FR_ACT_PROHIBIT => RuleAction::Blocked,
                FR_ACT_NOP => RuleAction::Nop,
                _ => RuleAction::Other,
            },
            table: u32::from(payload[4]),
            invert: flags & FIB_RULE_INVERT != 0,
            uid_range: None,
            mark: None,
            input_interface: None,
            undecidable: payload[1] != 0 || payload[2] != 0 || payload[3] != 0,
            suppress_prefix_len: None,
        };
        let (mut mark, mut mask) = (None, None);
        for (attribute, value) in attributes(payload, 12)? {
            match attribute {
                FRA_PRIORITY => rule.priority = attribute_u32(value)?,
                FRA_TABLE => rule.table = attribute_u32(value)?,
                FRA_FWMARK => mark = Some(attribute_u32(value)?),
                FRA_FWMASK => mask = Some(attribute_u32(value)?),
                // The kernel reports "no suppression" as all ones (-1).
                FRA_SUPPRESS_PREFIXLEN => {
                    rule.suppress_prefix_len =
                        Some(attribute_u32(value)?).filter(|limit| *limit != u32::MAX);
                }
                FRA_UID_RANGE if value.len() == 8 => {
                    rule.uid_range = Some((read_u32(value, 0)?, read_u32(value, 4)?));
                }
                FRA_IIFNAME => rule.input_interface = Some(interface_name(value)?),
                FRA_PROTOCOL | FRA_PAD | FRA_FLOW | FRA_SUPPRESS_IFGROUP => {}
                // Address or output-interface selectors, a jump target or a selector
                // from a newer kernel cannot be decided without a concrete packet.
                _ => rule.undecidable = true,
            }
        }
        // The kernel emits the mask whenever a mark selector exists and defaults
        // a given mark to an all-ones mask.
        if mark.is_some() || mask.is_some() {
            let value = mark.unwrap_or(0);
            rule.mark = Some((value, mask.unwrap_or(if value != 0 { u32::MAX } else { 0 })));
        }
        rules.push(rule);
    }
    Some(rules)
}

/// Any default route of the family that leaves through `target_index`, in any
/// table. This is the observer's baseline evidence; it does not say which
/// identity the route applies to.
pub fn default_route_via(routes: &[Route], family: u8, target_index: u32) -> bool {
    routes.iter().any(|route| {
        route.family == family
            && route.prefix_len == 0
            && route.kind == RouteKind::Unicast
            && route.output_index == Some(target_index)
    })
}

/// Every outcome the egress identity's unmarked packets could have.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Paths {
    pub tunnel: bool,
    /// Dropped or rejected by a blackhole, unreachable or prohibit entry.
    pub blocked: bool,
    /// No rule and table yields a route.
    pub none: bool,
    /// Leaves through an interface other than the tunnel (or an unprovable one).
    pub direct: bool,
}

impl Paths {
    /// The only possible outcome is the tunnel.
    pub fn only_tunnel(self) -> bool {
        self.tunnel && !self.blocked && !self.none && !self.direct
    }

    /// No possible outcome leaves through another interface. Blocked or absent
    /// paths contain traffic; a tunnel path is permitted.
    pub fn contained(self) -> bool {
        !self.direct
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Match {
    Yes,
    No,
    Maybe,
}

/// Whether `rule` applies to an unmarked, locally generated packet of `uid`.
fn matches(rule: &Rule, uid: u32) -> Match {
    let mut result = Match::Yes;
    if rule
        .uid_range
        .is_some_and(|(start, end)| !(start..=end).contains(&uid))
    {
        result = Match::No;
    }
    // An unmarked packet has mark 0: the selector matches iff value & mask == 0.
    if rule.mark.is_some_and(|(value, mask)| value & mask != 0) {
        result = Match::No;
    }
    // Locally generated packets carry the loopback as input interface.
    if rule
        .input_interface
        .as_deref()
        .is_some_and(|name| name != "lo")
    {
        result = Match::No;
    }
    if result == Match::Yes && rule.undecidable {
        result = Match::Maybe;
    }
    match (rule.invert, result) {
        (true, Match::Yes) => Match::No,
        (true, Match::No) => Match::Yes,
        (_, other) => other,
    }
}

fn covers(route: &Route, destination: IpAddr) -> bool {
    let Some(prefix) = route.destination else {
        return route.prefix_len == 0;
    };
    let (prefix, destination) = match (prefix, destination) {
        (IpAddr::V4(prefix), IpAddr::V4(destination)) => (
            u128::from(u32::from(prefix)) << 96,
            u128::from(u32::from(destination)) << 96,
        ),
        (IpAddr::V6(prefix), IpAddr::V6(destination)) => {
            (u128::from(prefix), u128::from(destination))
        }
        _ => return false,
    };
    let length = u32::from(route.prefix_len);
    length == 0 || (length <= 128 && (prefix ^ destination) >> (128 - length) == 0)
}

/// Add the outcomes of the best-matching route(s) of `table`. Equally specific
/// routes (multipath, metrics) are all counted, so a direct fallback beside a
/// tunnel route is never hidden. `None` means the table has no usable route.
fn lookup(
    routes: &[Route],
    family: u8,
    table: u32,
    destination: Option<IpAddr>,
    suppress: Option<u32>,
    tunnel_index: u32,
) -> Option<Paths> {
    let candidates = routes.iter().filter(|route| {
        route.family == family
            && route.table == table
            && match destination {
                None => route.prefix_len == 0,
                Some(destination) => covers(route, destination),
            }
    });
    let best = candidates.clone().map(|route| route.prefix_len).max()?;
    if suppress.is_some_and(|limit| u32::from(best) <= limit) {
        return None;
    }
    let mut paths = Paths::default();
    for route in candidates.filter(|route| route.prefix_len == best) {
        match route.kind {
            RouteKind::Blocked => paths.blocked = true,
            RouteKind::Unicast if route.output_index == Some(tunnel_index) => paths.tunnel = true,
            RouteKind::Unicast | RouteKind::Other => paths.direct = true,
        }
    }
    Some(paths)
}

/// Where unmarked packets of `uid` (towards `destination`, or a generic public
/// destination covered only by default routes) can leave in `family`.
pub fn evaluate(
    routes: &[Route],
    rules: &[Rule],
    family: u8,
    uid: u32,
    tunnel_index: u32,
    destination: Option<IpAddr>,
) -> Paths {
    let mut ordered: Vec<&Rule> = rules.iter().filter(|rule| rule.family == family).collect();
    ordered.sort_by_key(|rule| rule.priority);
    let mut paths = Paths::default();
    for rule in ordered {
        let applies = matches(rule, uid);
        if applies == Match::No {
            continue;
        }
        let outcome = match rule.action {
            RuleAction::Blocked => Some(Paths {
                blocked: true,
                ..Paths::default()
            }),
            RuleAction::Nop => None,
            // An action this evaluator does not understand (for example a jump)
            // must not be assumed safe.
            RuleAction::Other => Some(Paths {
                direct: true,
                ..Paths::default()
            }),
            RuleAction::ToTable => lookup(
                routes,
                family,
                rule.table,
                destination,
                rule.suppress_prefix_len,
                tunnel_index,
            ),
        };
        let Some(outcome) = outcome else { continue };
        paths.tunnel |= outcome.tunnel;
        paths.blocked |= outcome.blocked;
        paths.direct |= outcome.direct;
        if applies == Match::Yes {
            return paths;
        }
    }
    // Reached when no rule decides, or every deciding rule was only possible.
    paths.none = true;
    paths
}

/// The selected path evidence for the egress identity, per dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathReport {
    /// Unmarked IPv4 traffic can only use the tunnel.
    pub ipv4_tunnel: bool,
    /// No IPv6 outcome leaves through another interface.
    pub ipv6_contained: bool,
    /// Every configured resolver is reached only through the tunnel.
    pub dns_tunnel: bool,
}

impl PathReport {
    pub fn all(self) -> bool {
        self.ipv4_tunnel && self.ipv6_contained && self.dns_tunnel
    }
}

/// Evaluate IPv4, IPv6 and the configured resolvers for `uid`.
pub fn path_report(
    routes: &[Route],
    rules: &[Rule],
    uid: u32,
    tunnel_index: u32,
    resolvers: &[IpAddr],
) -> PathReport {
    PathReport {
        ipv4_tunnel: evaluate(routes, rules, AF_INET, uid, tunnel_index, None).only_tunnel(),
        ipv6_contained: evaluate(routes, rules, AF_INET6, uid, tunnel_index, None).contained(),
        dns_tunnel: resolvers.iter().all(|resolver| {
            let family = if resolver.is_ipv4() {
                AF_INET
            } else {
                AF_INET6
            };
            evaluate(routes, rules, family, uid, tunnel_index, Some(*resolver)).only_tunnel()
        }),
    }
}

/// Builders for synthetic NETLINK_ROUTE dumps, shared by the unit tests and the
/// namespace fixture. They describe layouts; they never touch host networking.
#[cfg(any(test, feature = "isolation-tests"))]
pub mod synthetic {
    use super::*;

    pub struct RouteSpec {
        pub family: u8,
        pub prefix_len: u8,
        pub destination: Option<IpAddr>,
        pub table: u32,
        pub kind: u8,
        pub output_index: Option<u32>,
    }

    impl RouteSpec {
        /// A unicast default route in `table` through `output_index`.
        pub fn default_route(family: u8, table: u32, output_index: u32) -> Self {
            Self {
                family,
                prefix_len: 0,
                destination: None,
                table,
                kind: RTN_UNICAST,
                output_index: Some(output_index),
            }
        }

        pub fn blocked(family: u8, table: u32) -> Self {
            Self {
                kind: RTN_BLACKHOLE,
                output_index: None,
                ..Self::default_route(family, table, 0)
            }
        }

        pub fn to(
            family: u8,
            destination: IpAddr,
            prefix_len: u8,
            table: u32,
            output_index: u32,
        ) -> Self {
            Self {
                destination: Some(destination),
                prefix_len,
                ..Self::default_route(family, table, output_index)
            }
        }
    }

    pub struct RuleSpec {
        pub family: u8,
        pub priority: u32,
        pub action: u8,
        pub table: u32,
        pub invert: bool,
        pub uid_range: Option<(u32, u32)>,
        pub mark: Option<(u32, u32)>,
        pub input_interface: Option<&'static str>,
        pub suppress_prefix_len: Option<u32>,
        pub source_len: u8,
    }

    impl RuleSpec {
        /// `ip rule add priority <priority> lookup <table>`.
        pub fn lookup(family: u8, priority: u32, table: u32) -> Self {
            Self {
                family,
                priority,
                action: FR_ACT_TO_TBL,
                table,
                invert: false,
                uid_range: None,
                mark: None,
                input_interface: None,
                suppress_prefix_len: None,
                source_len: 0,
            }
        }

        pub fn blackhole(family: u8, priority: u32) -> Self {
            Self {
                action: FR_ACT_BLACKHOLE,
                ..Self::lookup(family, priority, 0)
            }
        }
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = vec![0u8; align4(length)];
        bytes[0..2].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
        bytes[4..4 + value.len()].copy_from_slice(value);
        bytes
    }

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let mut bytes = vec![0u8; align4(length)];
        bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[16..16 + payload.len()].copy_from_slice(payload);
        bytes
    }

    pub fn done() -> Vec<u8> {
        message(NLMSG_DONE, &[])
    }

    pub fn error(errno: i32) -> Vec<u8> {
        message(NLMSG_ERROR, &errno.to_ne_bytes())
    }

    pub fn route(spec: &RouteSpec) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0] = spec.family;
        payload[1] = spec.prefix_len;
        // The single-byte table field is deliberately wrong for large tables.
        payload[4] = u8::try_from(spec.table).unwrap_or(252);
        payload[7] = spec.kind;
        if let Some(destination) = spec.destination {
            let octets = match destination {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            payload.extend(attribute(RTA_DST, &octets));
        }
        if let Some(index) = spec.output_index {
            payload.extend(attribute(RTA_OIF, &index.to_ne_bytes()));
        }
        payload.extend(attribute(RTA_TABLE, &spec.table.to_ne_bytes()));
        message(RTM_NEWROUTE, &payload)
    }

    pub fn rule(spec: &RuleSpec) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0] = spec.family;
        payload[2] = spec.source_len;
        payload[4] = u8::try_from(spec.table).unwrap_or(252);
        payload[7] = spec.action;
        let flags: u32 = if spec.invert { FIB_RULE_INVERT } else { 0 };
        payload[8..12].copy_from_slice(&flags.to_ne_bytes());
        payload.extend(attribute(FRA_PRIORITY, &spec.priority.to_ne_bytes()));
        payload.extend(attribute(FRA_TABLE, &spec.table.to_ne_bytes()));
        if let Some((value, mask)) = spec.mark {
            if value != 0 {
                payload.extend(attribute(FRA_FWMARK, &value.to_ne_bytes()));
            }
            payload.extend(attribute(FRA_FWMASK, &mask.to_ne_bytes()));
        }
        if let Some((start, end)) = spec.uid_range {
            let mut range = start.to_ne_bytes().to_vec();
            range.extend(end.to_ne_bytes());
            payload.extend(attribute(FRA_UID_RANGE, &range));
        }
        if let Some(name) = spec.input_interface {
            let mut name = name.as_bytes().to_vec();
            name.push(0);
            payload.extend(attribute(FRA_IIFNAME, &name));
        }
        if let Some(limit) = spec.suppress_prefix_len {
            payload.extend(attribute(FRA_SUPPRESS_PREFIXLEN, &limit.to_ne_bytes()));
        }
        message(RTM_NEWRULE, &payload)
    }

    /// One terminated dump of the given messages.
    pub fn dump(messages: &[Vec<u8>]) -> Vec<u8> {
        let mut dump: Vec<u8> = messages.concat();
        dump.extend(done());
        dump
    }
}

#[cfg(test)]
mod tests {
    use super::synthetic::*;
    use super::*;

    const TUNNEL: u32 = 7;
    const ETH: u32 = 2;
    const EGRESS_UID: u32 = 2;

    fn routes(specs: &[RouteSpec]) -> Vec<Route> {
        parse_routes(&dump(&specs.iter().map(route).collect::<Vec<_>>())).unwrap()
    }

    fn rules(specs: &[RuleSpec]) -> Vec<Rule> {
        parse_rules(&dump(&specs.iter().map(rule).collect::<Vec<_>>())).unwrap()
    }

    /// The three rules every kernel starts with.
    fn base(family: u8) -> Vec<RuleSpec> {
        vec![
            RuleSpec::lookup(family, 0, 255),
            RuleSpec::lookup(family, 32766, 254),
            RuleSpec::lookup(family, 32767, 253),
        ]
    }

    fn path(
        routes: &[Route],
        rules: &[Rule],
        family: u8,
        uid: u32,
        destination: Option<IpAddr>,
    ) -> Paths {
        evaluate(routes, rules, family, uid, TUNNEL, destination)
    }

    /// `wg-quick` layout: a main lookup that suppresses default routes (32764)
    /// ahead of the unmarked-traffic rule to the tunnel table (32765), while the
    /// host keeps a direct main default.
    fn wireguard(family: u8) -> (Vec<RouteSpec>, Vec<RuleSpec>) {
        let mut rules = base(family);
        rules.push(RuleSpec {
            invert: true,
            mark: Some((0xca6c, u32::MAX)),
            ..RuleSpec::lookup(family, 32765, 51820)
        });
        rules.push(RuleSpec {
            suppress_prefix_len: Some(0),
            ..RuleSpec::lookup(family, 32764, 254)
        });
        (
            vec![
                RouteSpec::default_route(family, 51820, TUNNEL),
                RouteSpec::default_route(family, 254, ETH),
            ],
            rules,
        )
    }

    #[test]
    fn wireguard_quick_layout_sends_unmarked_traffic_through_the_tunnel() {
        let (route_specs, rule_specs) = wireguard(AF_INET);
        let (routes, rules) = (routes(&route_specs), rules(&rule_specs));
        let paths = path(&routes, &rules, AF_INET, EGRESS_UID, None);
        assert!(paths.only_tunnel(), "{paths:?}");
        // The host itself still has a direct default, which the egress identity
        // never reaches because its unmarked packets match the tunnel rule first.
        assert!(default_route_via(&routes, AF_INET, ETH));
        // Outer WireGuard packets carry the mark and fall through to main.
        assert!(!default_route_via(&routes, AF_INET6, TUNNEL));
    }

    #[test]
    fn missing_tunnel_rule_exposes_the_direct_main_default() {
        let (route_specs, mut rule_specs) = wireguard(AF_INET);
        rule_specs.retain(|rule| rule.priority != 32765);
        let (routes, rules) = (routes(&route_specs), rules(&rule_specs));
        let paths = path(&routes, &rules, AF_INET, EGRESS_UID, None);
        // The suppressed main lookup skips the default; the plain main rule finds it.
        assert!(paths.direct && !paths.only_tunnel(), "{paths:?}");
    }

    #[test]
    fn tailscale_exit_node_layout_uses_table_52_for_unmarked_traffic() {
        // Rules 5210-5250 only match Tailscale's own marked packets.
        let mark = Some((0x80000, 0xff0000));
        let mut rule_specs = base(AF_INET);
        for (priority, table) in [(5210, 254), (5230, 253)] {
            rule_specs.push(RuleSpec {
                mark,
                ..RuleSpec::lookup(AF_INET, priority, table)
            });
        }
        rule_specs.push(RuleSpec {
            mark,
            ..RuleSpec::blackhole(AF_INET, 5250)
        });
        rule_specs.push(RuleSpec::lookup(AF_INET, 5270, 52));
        let routes = routes(&[
            RouteSpec::default_route(AF_INET, 52, TUNNEL),
            RouteSpec::default_route(AF_INET, 254, ETH),
        ]);
        let rules = rules(&rule_specs);
        assert!(path(&routes, &rules, AF_INET, EGRESS_UID, None).only_tunnel());
        assert!(default_route_via(&routes, AF_INET, TUNNEL));
    }

    #[test]
    fn uid_range_rule_steers_only_the_egress_identity() {
        let mut rule_specs = base(AF_INET);
        rule_specs.push(RuleSpec {
            uid_range: Some((2, 2)),
            ..RuleSpec::lookup(AF_INET, 100, 100)
        });
        let routes = routes(&[
            RouteSpec::default_route(AF_INET, 100, TUNNEL),
            RouteSpec::default_route(AF_INET, 254, ETH),
        ]);
        let rules = rules(&rule_specs);
        assert!(path(&routes, &rules, AF_INET, EGRESS_UID, None).only_tunnel());
        // Another identity takes the direct main default.
        let other = path(&routes, &rules, AF_INET, 1000, None);
        assert!(other.direct && !other.tunnel, "{other:?}");
    }

    #[test]
    fn a_direct_fallback_beside_the_tunnel_route_is_not_contained() {
        let mut rule_specs = base(AF_INET);
        rule_specs.push(RuleSpec::lookup(AF_INET, 100, 100));
        let routes = routes(&[
            RouteSpec::default_route(AF_INET, 100, TUNNEL),
            RouteSpec::default_route(AF_INET, 100, ETH),
        ]);
        let paths = path(&routes, &rules(&rule_specs), AF_INET, EGRESS_UID, None);
        assert!(paths.tunnel && paths.direct && !paths.only_tunnel());
    }

    #[test]
    fn rules_with_undecidable_selectors_count_as_possibly_matching() {
        let mut rule_specs = base(AF_INET);
        // `from 10.0.0.0/8 lookup 100` cannot be decided for a generic packet.
        rule_specs.push(RuleSpec {
            source_len: 8,
            ..RuleSpec::lookup(AF_INET, 100, 100)
        });
        let routes = routes(&[
            RouteSpec::default_route(AF_INET, 100, TUNNEL),
            RouteSpec::default_route(AF_INET, 254, ETH),
        ]);
        let paths = path(&routes, &rules(&rule_specs), AF_INET, EGRESS_UID, None);
        assert!(paths.tunnel && paths.direct, "{paths:?}");
        // A possibly matching rule never proves the tunnel on its own.
        assert!(!paths.only_tunnel());
    }

    #[test]
    fn ipv6_is_contained_by_a_tunnel_default_a_blocking_default_or_no_default() {
        let tunnel = routes(&[RouteSpec::default_route(AF_INET6, 254, TUNNEL)]);
        let blocked = routes(&[RouteSpec::blocked(AF_INET6, 254)]);
        let absent: Vec<Route> = Vec::new();
        let direct = routes(&[RouteSpec::default_route(AF_INET6, 254, ETH)]);
        let rules = rules(&base(AF_INET6));
        assert!(path(&tunnel, &rules, AF_INET6, EGRESS_UID, None).contained());
        assert!(path(&blocked, &rules, AF_INET6, EGRESS_UID, None).contained());
        assert!(path(&absent, &rules, AF_INET6, EGRESS_UID, None).contained());
        let leak = path(&direct, &rules, AF_INET6, EGRESS_UID, None);
        assert!(!leak.contained() && leak.direct, "{leak:?}");
        // A rule dump without IPv6 (IPv6 unavailable) leaves no IPv6 path at all.
        assert!(path(&direct, &[], AF_INET6, EGRESS_UID, None).contained());
    }

    #[test]
    fn a_blackhole_rule_ahead_of_the_main_lookup_blocks_the_path() {
        let mut rule_specs = base(AF_INET6);
        rule_specs.push(RuleSpec::blackhole(AF_INET6, 100));
        let routes = routes(&[RouteSpec::default_route(AF_INET6, 254, ETH)]);
        let paths = path(&routes, &rules(&rule_specs), AF_INET6, EGRESS_UID, None);
        assert!(
            paths.blocked && paths.contained() && !paths.direct,
            "{paths:?}"
        );
    }

    #[test]
    fn resolver_routes_use_the_longest_matching_prefix() {
        let resolver: IpAddr = "9.9.9.9".parse().unwrap();
        let (mut route_specs, rule_specs) = wireguard(AF_INET);
        let routes_ok = routes(&route_specs);
        let rules = rules(&rule_specs);
        let ok = path(&routes_ok, &rules, AF_INET, EGRESS_UID, Some(resolver));
        assert!(ok.only_tunnel(), "{ok:?}");
        // A more specific route to the resolver's network via the physical link,
        // placed in the table the unmarked rule selects, is a DNS leak.
        route_specs.push(RouteSpec::to(
            AF_INET,
            "9.9.9.0".parse().unwrap(),
            24,
            51820,
            ETH,
        ));
        let leak = path(
            &routes(&route_specs),
            &rules,
            AF_INET,
            EGRESS_UID,
            Some(resolver),
        );
        assert!(leak.direct && !leak.only_tunnel(), "{leak:?}");
        // Another resolver outside that prefix still uses the tunnel default.
        let other: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(
            path(
                &routes(&route_specs),
                &rules,
                AF_INET,
                EGRESS_UID,
                Some(other)
            )
            .only_tunnel()
        );
    }

    #[test]
    fn a_resolver_on_a_connected_tunnel_network_is_found_in_main_ahead_of_the_tunnel_table() {
        let resolver: IpAddr = "9.9.9.9".parse().unwrap();
        let (mut route_specs, rule_specs) = wireguard(AF_INET);
        // The tunnel's own address range is a connected route in the main table.
        route_specs.push(RouteSpec::to(
            AF_INET,
            "9.9.9.0".parse().unwrap(),
            24,
            254,
            TUNNEL,
        ));
        let rules = rules(&rule_specs);
        let ok = path(
            &routes(&route_specs),
            &rules,
            AF_INET,
            EGRESS_UID,
            Some(resolver),
        );
        assert!(ok.only_tunnel(), "{ok:?}");
        // The same prefix on the physical link would be a leak found in main first.
        route_specs.pop();
        route_specs.push(RouteSpec::to(
            AF_INET,
            "9.9.9.0".parse().unwrap(),
            24,
            254,
            ETH,
        ));
        let leak = path(
            &routes(&route_specs),
            &rules,
            AF_INET,
            EGRESS_UID,
            Some(resolver),
        );
        assert!(leak.direct && !leak.only_tunnel(), "{leak:?}");
    }

    #[test]
    fn ipv6_resolver_prefixes_are_matched_bitwise() {
        let resolver: IpAddr = "2620:fe::fe".parse().unwrap();
        let specs = [
            RouteSpec::default_route(AF_INET6, 254, TUNNEL),
            RouteSpec::to(AF_INET6, "2620:fe::".parse().unwrap(), 48, 254, ETH),
        ];
        let paths = path(
            &routes(&specs),
            &rules(&base(AF_INET6)),
            AF_INET6,
            2,
            Some(resolver),
        );
        assert!(paths.direct && !paths.only_tunnel(), "{paths:?}");
        let near: IpAddr = "2620:ff::1".parse().unwrap();
        assert!(
            path(
                &routes(&specs),
                &rules(&base(AF_INET6)),
                AF_INET6,
                2,
                Some(near)
            )
            .only_tunnel()
        );
    }

    #[test]
    fn the_path_report_separates_ipv4_ipv6_and_dns() {
        let resolvers: Vec<IpAddr> =
            vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()];
        let (mut v4_routes, mut rule_specs) = wireguard(AF_INET);
        let (v6_routes, v6_rules) = wireguard(AF_INET6);
        v4_routes.extend(v6_routes);
        rule_specs.extend(v6_rules);
        let (parsed_routes, parsed_rules) = (routes(&v4_routes), rules(&rule_specs));
        let ready = path_report(
            &parsed_routes,
            &parsed_rules,
            EGRESS_UID,
            TUNNEL,
            &resolvers,
        );
        assert!(ready.all(), "{ready:?}");

        // IPv6 loses its tunnel rule: the physical IPv6 default is reachable, so
        // IPv6 and the IPv6 resolver leak while IPv4 stays in the tunnel.
        let mut leaking = rule_specs;
        leaking.retain(|rule| !(rule.family == AF_INET6 && rule.priority == 32765));
        let report = path_report(
            &parsed_routes,
            &rules(&leaking),
            EGRESS_UID,
            TUNNEL,
            &resolvers,
        );
        assert!(
            report.ipv4_tunnel && !report.ipv6_contained && !report.dns_tunnel,
            "{report:?}"
        );

        // DNS only: a resolver prefix routed through the physical link.
        let mut dns_routes = v4_routes;
        dns_routes.push(RouteSpec::to(
            AF_INET,
            "9.9.9.0".parse().unwrap(),
            24,
            51820,
            ETH,
        ));
        let report = path_report(
            &routes(&dns_routes),
            &parsed_rules,
            EGRESS_UID,
            TUNNEL,
            &resolvers,
        );
        assert!(
            report.ipv4_tunnel && report.ipv6_contained && !report.dns_tunnel,
            "{report:?}"
        );
        // Without a configured resolver there is no DNS evidence to fail.
        assert!(path_report(&parsed_routes, &parsed_rules, EGRESS_UID, TUNNEL, &[]).dns_tunnel);
    }

    #[test]
    fn multipath_or_nexthop_routes_never_prove_the_tunnel() {
        let mut spec = RouteSpec::default_route(AF_INET, 254, TUNNEL);
        spec.output_index = None;
        let routes = routes(&[spec]);
        let paths = path(&routes, &rules(&base(AF_INET)), AF_INET, EGRESS_UID, None);
        assert!(paths.direct && !paths.only_tunnel());
        assert!(!default_route_via(&routes, AF_INET, TUNNEL));
    }

    #[test]
    fn existing_default_route_semantics_cover_every_table_and_family() {
        let routes = routes(&[
            RouteSpec::default_route(AF_INET, 52, TUNNEL),
            RouteSpec::to(AF_INET, "10.0.0.0".parse().unwrap(), 24, 52, 3),
            RouteSpec::default_route(AF_INET6, 52, 9),
        ]);
        assert!(default_route_via(&routes, AF_INET, TUNNEL));
        assert!(
            !default_route_via(&routes, AF_INET, 3),
            "not a default route"
        );
        assert!(
            !default_route_via(&routes, AF_INET, 9),
            "IPv6 is a different family"
        );
        assert!(default_route_via(&routes, AF_INET6, 9));
    }

    #[test]
    fn truncated_unterminated_or_failing_dumps_are_not_evidence() {
        let message = route(&RouteSpec::default_route(AF_INET, 52, TUNNEL));
        assert!(parse_routes(&message).is_none(), "no NLMSG_DONE");
        assert!(parse_routes(&message[..4]).is_none());
        assert!(parse_routes(&[]).is_none());
        assert!(!dump_complete(&message));
        assert!(dump_complete(&dump(std::slice::from_ref(&message))));
        let mut failing = error(-1);
        failing.extend(done());
        assert!(parse_routes(&failing).is_none());
        // A malformed attribute poisons the whole dump rather than being skipped.
        let mut bad = message;
        bad[16 + 12..16 + 14].copy_from_slice(&2u16.to_ne_bytes());
        assert!(parse_routes(&dump(&[bad])).is_none());
    }

    #[test]
    fn concatenated_dumps_are_parsed_as_one_evidence_set() {
        let mut both = dump(&[route(&RouteSpec::default_route(AF_INET, 52, TUNNEL))]);
        both.extend(dump(&[route(&RouteSpec::default_route(
            AF_INET6, 52, TUNNEL,
        ))]));
        let routes = parse_routes(&both).unwrap();
        assert_eq!(routes.len(), 2);
        // The second dump must also be terminated.
        both.truncate(both.len() - 16);
        assert!(parse_routes(&both).is_none());
    }

    #[test]
    fn rule_parsing_keeps_selectors_priority_and_suppression() {
        let parsed = rules(&[RuleSpec {
            uid_range: Some((10, 20)),
            mark: Some((0x5, 0xff)),
            input_interface: Some("lo"),
            suppress_prefix_len: Some(0),
            ..RuleSpec::lookup(AF_INET, 77, 300)
        }]);
        let rule = &parsed[0];
        assert_eq!(
            (rule.priority, rule.table, rule.uid_range, rule.mark),
            (77, 300, Some((10, 20)), Some((0x5, 0xff)))
        );
        assert_eq!(rule.input_interface.as_deref(), Some("lo"));
        assert_eq!(rule.suppress_prefix_len, Some(0));
        assert!(!rule.undecidable && !rule.invert);
        // Large tables are read from FRA_TABLE, not the one-byte header field.
        assert_eq!(parsed[0].table, 300);
    }

    #[test]
    fn mark_selectors_are_evaluated_for_an_unmarked_packet() {
        let inverted = |value| Rule {
            invert: true,
            mark: Some((value, u32::MAX)),
            ..rules(&[RuleSpec::lookup(AF_INET, 1, 1)])[0].clone()
        };
        // `not fwmark X`: an unmarked packet matches whenever X != 0.
        assert!(matches(&inverted(0xca6c), 2) == Match::Yes);
        assert!(matches(&inverted(0), 2) == Match::No);
        // A foreign input interface never matches locally generated packets.
        let foreign = Rule {
            input_interface: Some("eth0".into()),
            ..rules(&[RuleSpec::lookup(AF_INET, 1, 1)])[0].clone()
        };
        assert!(matches(&foreign, 2) == Match::No);
    }

    /// Dumps recorded from a real kernel (6.18, little endian) in a private network
    /// namespace with the layout of the VM test: interface indexes 2 (wg0, the
    /// tunnel), 3 (eth2), 4 (eth0), `default via eth0` in main, `default dev wg0` in
    /// table 51820 and the two `wg-quick` rules. The kernel reports "no
    /// suppression" as `FRA_SUPPRESS_PREFIXLEN` = -1, which synthetic dumps never
    /// showed and which once made every table lookup look suppressed.
    #[cfg(target_endian = "little")]
    mod recorded {
        use super::*;

        fn bytes(hex: &str) -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                .collect()
        }

        fn dumps() -> (Vec<Route>, Vec<Rule>) {
            let mut routes = bytes(ROUTES4);
            routes.extend(bytes(ROUTES6));
            let mut rules = bytes(RULES4);
            rules.extend(bytes(RULES6));
            (parse_routes(&routes).unwrap(), parse_rules(&rules).unwrap())
        }

        const RULES4: &str = concat!(
            "3400000020000200010000000b990a0002000000ff0000010000000008000f00ff00000008000e00ffffffff05001500",
            "020000003c00000020000200010000000b990a0002000000fe0000010000000008000f00fe00000008000e0000000000",
            "050015000000000008000600fc7f00004c00000020000200010000000b990a0002000000fc0000010200000008000f00",
            "6cca000008000e00ffffffff050015000000000008000600fd7f000008000a004752000008001000ffffffff3c000000",
            "20000200010000000b990a0002000000fe0000010000000008000f00fe00000008000e00ffffffff0500150002000000",
            "08000600fe7f00003c00000020000200010000000b990a0002000000fd0000010000000008000f00fd00000008000e00",
            "ffffffff050015000200000008000600ff7f00001400000003000200010000000b990a0000000000",
        );
        const ROUTES4: &str = concat!(
            "2c00000018000200010000000b990a0002000000fc03fd010000000008000f006cca0000080004000200000034000000",
            "18000200010000000b990a0002000000fe0300010000000008000f00fe000000080005000a0002020800040004000000",
            "3c00000018000200010000000b990a0002180000fe02fd010000000008000f00fe000000080001000909090008000700",
            "0909090108000400020000003c00000018000200010000000b990a0002180000fe02fd010000000008000f00fe000000",
            "080001000a000200080007000a00020f08000400040000003c00000018000200010000000b990a0002180000fe02fd01",
            "0000000008000f00fe000000080001000a170000080007000a17000108000400020000003c0000001800020001000000",
            "0b990a0002180000fe02fd010000000008000f00fe00000008000100c633640008000700c63364010800040003000000",
            "3c00000018000200010000000b990a0002200000ff02fe020000000008000f00ff000000080001000909090108000700",
            "0909090108000400020000003c00000018000200010000000b990a0002200000ff02fd030000000008000f00ff000000",
            "08000100090909ff080007000909090108000400020000003c00000018000200010000000b990a0002200000ff02fe02",
            "0000000008000f00ff000000080001000a00020f080007000a00020f08000400040000003c0000001800020001000000",
            "0b990a0002200000ff02fd030000000008000f00ff000000080001000a0002ff080007000a00020f0800040004000000",
            "3c00000018000200010000000b990a0002200000ff02fe020000000008000f00ff000000080001000a17000108000700",
            "0a17000108000400020000003c00000018000200010000000b990a0002200000ff02fd030000000008000f00ff000000",
            "080001000a1700ff080007000a17000108000400020000003c00000018000200010000000b990a0002080000ff02fe02",
            "0000000008000f00ff000000080001007f000000080007007f00000108000400010000003c0000001800020001000000",
            "0b990a0002200000ff02fe020000000008000f00ff000000080001007f000001080007007f0000010800040001000000",
            "3c00000018000200010000000b990a0002200000ff02fd030000000008000f00ff000000080001007fffffff08000700",
            "7f00000108000400010000003c00000018000200010000000b990a0002200000ff02fe020000000008000f00ff000000",
            "08000100c633640108000700c633640108000400030000003c00000018000200010000000b990a0002200000ff02fd03",
            "0000000008000f00ff00000008000100c63364ff08000700c63364010800040003000000140000000300020001000000",
            "0b990a0000000000",
        );
        const RULES6: &str = concat!(
            "3400000020000200010000000b990a000a000000ff0000010000000008000f00ff00000008000e00ffffffff05001500",
            "020000003c00000020000200010000000b990a000a000000fe0000010000000008000f00fe00000008000e00ffffffff",
            "050015000200000008000600fe7f00001400000003000200010000000b990a0000000000",
        );
        const ROUTES6: &str = concat!(
            "7400000018000200010000000b990a000a400000fe0200010000000008000f00fe00000014000100fe80000000000000",
            "00000000000000000800060000010000080004000200000024000c000000000000000000000000000000000000000000",
            "00000000000000000000000005001400000000007400000018000200010000000b990a000a400000fe02000100000000",
            "08000f00fe00000014000100fe8000000000000000000000000000000800060000010000080004000300000024000c00",
            "000000000000000000000000000000000000000000000000000000000000000005001400000000007400000018000200",
            "010000000b990a000a400000fe0200010000000008000f00fe00000014000100fe800000000000000000000000000000",
            "0800060000010000080004000400000024000c0000000000000000000000000000000000000000000000000000000000",
            "0000000005001400000000007400000018000200010000000b990a000a800000ff0200020000000008000f00ff000000",
            "14000100000000000000000000000000000000010800060000000000080004000100000024000c000000000000000000",
            "00000000000000000000000000000000000000000000000005001400000000007400000018000200010000000b990a00",
            "0a800000ff0200020000000008000f00ff00000014000100fe80000000000000506284fffec65a670800060000000000",
            "080004000400000024000c00000000000000000000000000000000000000000000000000000000000000000005001400",
            "000000007400000018000200010000000b990a000a800000ff0200020000000008000f00ff00000014000100fe800000",
            "00000000a04930fffec534710800060000000000080004000200000024000c0000000000000000000000000000000000",
            "0000000000000000000000000000000005001400000000007400000018000200010000000b990a000a800000ff020002",
            "0000000008000f00ff00000014000100fe80000000000000c07632fffe61909008000600000000000800040003000000",
            "24000c000000000000000000000000000000000000000000000000000000000000000000050014000000000074000000",
            "18000200010000000b990a000a080000ff0200050000000008000f00ff00000014000100ff0000000000000000000000",
            "000000000800060000010000080004000200000024000c00000000000000000000000000000000000000000000000000",
            "000000000000000005001400000000007400000018000200010000000b990a000a080000ff0200050000000008000f00",
            "ff00000014000100ff0000000000000000000000000000000800060000010000080004000300000024000c0000000000",
            "000000000000000000000000000000000000000000000000000000000500140000000000740000001800020001000000",
            "0b990a000a080000ff0200050000000008000f00ff00000014000100ff00000000000000000000000000000008000600",
            "00010000080004000400000024000c000000000000000000000000000000000000000000000000000000000000000000",
            "05001400000000001400000003000200010000000b990a0000000000",
        );

        #[test]
        fn a_real_wg_quick_layout_is_parsed_and_proves_the_tunnel_path() {
            let (routes, rules) = dumps();
            let unsuppressed = rules
                .iter()
                .filter(|rule| rule.suppress_prefix_len.is_none());
            assert_eq!(
                unsuppressed.count(),
                rules.len() - 1,
                "only one rule suppresses"
            );
            assert!(default_route_via(&routes, AF_INET, 2));
            assert!(
                default_route_via(&routes, AF_INET, 4),
                "the host keeps a direct default"
            );
            let report = path_report(&routes, &rules, 4002, 2, &["9.9.9.9".parse().unwrap()]);
            assert!(report.all(), "{report:?}");
            // The same real dump with the tunnel rule removed exposes the direct default.
            let without_tunnel_rule: Vec<Rule> = rules
                .iter()
                .filter(|rule| !(rule.family == AF_INET && rule.priority == 32765))
                .cloned()
                .collect();
            let leak = path_report(&routes, &without_tunnel_rule, 4002, 2, &[]);
            assert!(!leak.ipv4_tunnel, "{leak:?}");
        }
    }
}
