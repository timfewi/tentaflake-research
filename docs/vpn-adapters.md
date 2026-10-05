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
| E7 Tunnel liveness and identity | The configured peer is alive and is the intended exit | WireGuard only: `--handshake-within` (a recent handshake) and `--peer-public-key` (the peers are exactly the pinned keys), from the kernel's WireGuard netlink dump. Other implementations: **not observed** | offline when selected and not met |
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

WireGuard authenticates every handshake with the peer's key, so a recent
handshake shows that the configured peer is alive and the peer set is the exit's
identity. `--handshake-within SECONDS` requires the peers to have completed a
handshake within the window (use 180 or more: a session expires after 180 s and a
keepalive tunnel re-handshakes about every two minutes), and `--peer-public-key`
(repeatable, at most four) requires the interface's peers to be exactly the pinned
keys; both need `--link-kind wireguard`. A dead tunnel is therefore detected only
when its last handshake ages out (up to the window); a vanished interface, route or
peer is detected at once.

The data comes from the kernel's WireGuard generic-netlink device dump, which needs
`CAP_NET_ADMIN` (the module adds exactly that capability to the observer unit when
this evidence is selected). The same dump also carries the interface's private key
and any preshared keys. The observer parses only each peer's public key and
handshake time, never copies, stores or logs a secret attribute, and scrubs the
receive buffers. Public keys are not secret and appear in the configuration.

An interface's received-packet counter is **not** a usable liveness signal: with
persistent keepalive on both ends only one side emits keepalives (every received
packet resets the other side's timer), so the passive side's counter stands still
on a healthy tunnel. Other VPN implementations (for example Tailscale's tun) have
no such evidence here; an adapter that needs it must run as root, publish an
ordinary lease, expose no key material and report `offline` as soon as its proof
lapses. Until then the exit region and identity are operator assertions.

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
| `handshakeWithinSeconds`, `peerPublicKeys` | `--handshake-within`, `--peer-public-key` | E7 liveness and identity (WireGuard) |
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

- Unit tests: route, rule and WireGuard dump parsing, the conservative evaluation
  (IPv4, IPv6, DNS, policy routing, direct-path denial, a recorded real-kernel
  dump), the observer state machine including draining, and an
  observer-to-controller chain covering tunnel loss, exit change, planned draining
  and its deadline, stale leases, observer and controller restart, and recovery.
- `scripts/check vpn-observer` runs the real binary as namespace-root against
  synthetic layouts: leak detection per dimension, link kind, handshake age and peer
  pins, malformed dumps, planned draining, an untrustworthy drain marker,
  diagnostics without addresses, keys or paths, locking and shutdown.
- `checks.x86_64-linux.network-boundary-wireguard-vm` runs the real observer and
  controller against a real WireGuard tunnel in a disposable VM, in the layout
  `wg-quick` creates: the readiness lease for the proxy comes from the chain, and
  the test removes the tunnel rule (IPv4 and IPv6), adds an unexpected peer, takes
  the tunnel interface down, drains for a planned exit change and kills the
  observer and the controller. The kernel firewall tests in the same VM still run.
- The firewall VM tests ([network-boundary.md](network-boundary.md)) cover
  direct-path denial, IPv4/IPv6 and DNS packets for the kernel rules.

Not shown: another VPN implementation (for example a Tailscale exit node) driving
the observer, E7 for anything but WireGuard, detection of a stale handshake in the
VM (the window is 190 s; the namespace fixture covers it), the rule set the
firewall actually loaded, or acceptance on a production host. VM and synthetic
results are not production acceptance.
