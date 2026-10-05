# VPN readiness adapters: evidence requirements

Research accepts any root-owned producer of the generic observation lease in
[egress-control.md](egress-control.md); no VPN vendor is required. This page says
what an adapter must observe before it may report `ready`, what stays an operator
assertion, and what the optional reference observer (`research-vpn-observer`)
proves. Management membership is separate from Internet exit readiness: a
control plane such as Headscale manages clients and does not supply an exit node,
so enrolment alone is never evidence of an exit.

## Evidence classes

| Class | Meaning | May make an exit `ready` |
| --- | --- | --- |
| Observed | Derived by the root adapter from kernel state at each refresh | Yes |
| Asserted | Declared by the operator: firewall marker, exit region | No; it can only withhold readiness |
| Enforced | The independent kernel firewall ([network-boundary.md](network-boundary.md)) | Not an input; it stays fail-closed if the adapter and controller both fail |

A firewall marker or a declared region never substitutes for observed evidence,
and neither is observed tunnel identity.

## Required evidence

| ID | Requirement | Reference observer | Failure |
| --- | --- | --- | --- |
| E1 Link | The tunnel interface exists and has `IFF_UP`; optionally it is the selected kind of link | Always; `--link-kind wireguard` (uevent `DEVTYPE=wireguard`) or `tun` (`tun_flags`) | offline |
| E2 IPv4 path | Unmarked IPv4 traffic of the egress identity can only leave through the tunnel | Baseline: a default route via the interface in any table. `--egress-uid`: rule-by-rule evaluation | offline |
| E3 IPv6 | No IPv6 outcome leaves through another interface: a tunnel route, a blackhole/unreachable/prohibit entry or no route all contain; a kernel without IPv6 contains | `--egress-uid` | offline |
| E4 DNS | Every configured resolver is reached only through the tunnel for the egress identity | `--dns-resolver` (requires `--egress-uid`), longest-prefix match | offline |
| E5 Policy routing | Rules are applied in kernel order: priority, `uidrange`, `fwmark`/mask, `not` (inverted), input interface and `suppress_prefixlength` | `--egress-uid` | offline |
| E6 Direct-path denial | No possible outcome of E2/E3/E5 uses a non-tunnel interface; a direct fallback beside a tunnel route counts as a leak | `--egress-uid` | offline |
| E7 Tunnel liveness and identity | Recent handshake, pinned peer key or exit identity | **Not observed** (see below) | n/a |
| E8 Firewall | The kernel rules exist | Marker only: an assertion | offline without the marker |
| E9 Region | The exit region | Declared only: an assertion | offline if malformed |

E5/E6 are decided conservatively. A selector that a generic public destination
cannot decide (source/destination prefix, TOS, ports, protocol, output interface,
VRF, an unknown attribute) makes a rule *possibly* matching, and every possible
outcome is collected. An unknown rule action, a multipath or nexthop-object route
(no single output interface) and a malformed, truncated or error-carrying dump are
never treated as proof. Specific non-default routes outside the resolver
destinations are not evaluated; the kernel firewall remains the guarantee for
them.

Typical layouts the evaluation understands, all verified with synthetic dumps:
`wg-quick` (`not fwmark X lookup <table>` plus `lookup main suppress_prefixlength
0`), a Tailscale exit node (marked `fwmark` rules ahead of `lookup 52`) and a
`uidrange` rule steering only the egress identity.

### E7: tunnel liveness and exit identity

Reading a WireGuard handshake or a peer key needs the WireGuard netlink family or
the VPN client's control interface, and must never read private keys or
credentials. The reference observer does not do this. An adapter that needs it
must run as root, publish an ordinary lease, expose no key material and report
`offline` as soon as its proof lapses. Until then the exit region and identity are
operator assertions.

## Lease and lifecycle requirements

The generic contract applies unchanged: leases live at most ten seconds, files and
ancestors are root-owned, and the controller grants at most three seconds beyond
its own poll.

- **Tunnel loss** reports `offline` immediately, without a region. Recovery starts
  a new generation; a lost exit is never resumed.
- **Exit change** (including a region change) starts a new generation.
- **Planned exit change:** report `draining` with the current generation only while
  the previous reading was `ready` (or `draining`) and every evidence class still
  holds, then change the exit, then report `ready` under a new generation.
  Draining without a prior `ready`, or with lost evidence, is `offline`. The
  controller bounds the drain with its own monotonic deadline (1–300 s); repeated
  heartbeats cannot extend it.
- **Stale or dead adapter:** the last lease expires within ten seconds. A restarted
  adapter or controller mints a new generation, so old jobs and browser sessions
  are interrupted.
- **Independent enforcement:** the egress firewall stays fail-closed with the
  adapter, the controller or both dead.

## Reference observer selection

Everything beyond the baseline is selected explicitly; the default behavior is
unchanged. Options of `services.secureResearch.vpnObserver`:

| Option | Flag | Effect |
| --- | --- | --- |
| `linkKind` | `--link-kind` | E1 link kind |
| `egressPathEvidence` | `--egress-uid`, one `--dns-resolver` per configured resolver | E2–E6 for the egress identity |
| `drainMarker` | `--drain-marker` | Planned exit change |

A planned exit change: create the root-owned drain marker, wait for the
controller to report draining (or for existing work to finish), change the exit,
remove the marker. The observer then re-proves everything and publishes `ready`
under a new generation, even if the exit turned out unchanged. A marker that is
missing is "no drain"; a marker that exists but is not a regular, root-owned file
without group/world write access, or whose parent directories are writable by
other identities, makes the exit offline (startup refuses such a path).

## Authority boundary

The observer reads sysfs, NETLINK_ROUTE route and rule dumps and regular marker
files. It runs no command or readiness hook, reads no VPN credential, and its
diagnostics are fixed events without addresses, interface names, paths or the
chosen implementation. Agents cannot choose an exit, write an observation, run a
readiness hook or reach VPN credentials: the observation and control directories
are root-owned and projected read-only to service identities.

## Evidence in this repository

- Unit tests: route and rule parsing, the conservative evaluation (IPv4, IPv6,
  DNS, policy routing, direct-path denial), the observer state machine including
  draining, and an observer-to-controller chain covering tunnel loss, exit change,
  planned draining and its deadline, stale leases, observer and controller restart,
  and recovery.
- `scripts/check vpn-observer` runs the real binary as namespace-root against
  synthetic layouts: leak detection per dimension, link kind, malformed dumps,
  planned draining, an untrustworthy drain marker, diagnostics without addresses or
  paths, locking and shutdown.
- The firewall VM tests ([network-boundary.md](network-boundary.md)) cover direct-path
  denial, IPv4/IPv6 and DNS packets for the kernel rules.

Not shown: a real tunnel or exit node driving the observer, E7, the rule set the
firewall actually loaded, or acceptance on a production host. Synthetic results
are not production acceptance.
