# Root-controlled egress leases

`research-egress-control` translates a root-owned observation from the operator's
VPN/firewall adapter into short research-specific leases. It is included in the
`research-egress` package output. The controller is implemented, and a reference
`research-vpn-observer` producer is implemented but **disabled by default** (the
operator may supply their own adapter). Host activation, NixOS unit acceptance and
packet-level acceptance are still pending. Do not activate it on the host as part
of source development.

## Trust and adapter contract

The adapter must prove the intended VPN exit and VPN-only egress-UID firewall,
including IPv4, IPv6 and DNS, before declaring readiness. Interface presence or
`IFF_UP` alone is insufficient. Research tools cannot write observations, choose
an exit, change firewall policy or execute a readiness command. The controller
does not run shell hooks, resolve targets or independently establish VPN health.

Input is a JSON `EgressState` with exactly these fields:

| Field | Contract |
| --- | --- |
| `version` | Integer `1` |
| `generation` | Non-nil UUID identifying the observed exit epoch |
| `mode` | `ready`, `draining` or `offline` |
| `region` | Optional ISO 3166-1 alpha-2 uppercase exit region. Absent is valid; anything else than `None` or exactly two ASCII uppercase letters makes the whole lease invalid |
| `valid_until` | Unix timestamp in seconds, later than now and at most ten seconds ahead |

The adapter atomically replaces the file and refreshes it while its proof is
valid. It must change the observed generation whenever the exit changes or proof
of uninterrupted protection is lost, even if interruption occurs between two
controller polls. Missing, expired, malformed or insecure input is offline.
The file must be regular, root-owned, at most 4096 bytes and not group/world
writable. All ancestors must be root-owned, non-writable to other identities and
non-symlink directories. Use `/run/...`, not a `/var/run` symlink or `/tmp`.

For a planned exit change, report `draining` with the old generation before
changing anything. Existing work may continue only while that old path and
firewall remain protected. New admission stops. Wait for completion, or the
configured drain deadline, before changing the exit. Then report `ready` with a
new observed generation after fresh proof. Unexpected loss must immediately
report `offline`; the independent firewall must remain fail-closed even if the
adapter and controller both fail.

## Reference observer

`research-vpn-observer` is an optional root producer that writes the observation
lease above. It is **disabled by default** in the module (`vpnObserver.enable`)
because the operator may already have an adapter; enabling it never fabricates
readiness — it only publishes what the checks below prove. It runs as root and
requires its output directory to be root-controlled and distinct from the
controller's control directory.

```text
research-vpn-observer --interface wg0 --output /run/research-vpn/observation.json \
  --refresh-seconds 5 --region DE --firewall-marker /run/research-vpn/firewall.marker
```

The renewal cadence is configurable from one to five seconds. Ready and Offline
publications use the existing ten-second maximum lease lifetime independently of
that cadence. The default therefore has five seconds of renewal headroom for
fractional wall-clock truncation and bounded collection/scheduling delay while a
dead observer still fails closed within the original ten-second contract bound.

Each refresh gathers four pieces of local, non-cryptographic evidence:

- `interface_up`: `/sys/class/net/<interface>/flags` exists and has `IFF_UP`
  (`0x1`) set.
- `default_route`: a live `NETLINK_ROUTE` dump contains a default IPv4 route
  (destination length 0) whose `RTA_OIF` equals the interface index of
  `--interface`, searched across **every** routing table. Tailscale's exit-node
  feature installs the default route in a policy-routing table (e.g. table 52),
  which the main-table-only `/proc/net/route` view would miss.
- `firewall_marker`: the configured path is a regular file, root-owned and not
  group/world writable. The operator's firewall installer creates it; it is a
  marker, not proof of the rules.
- `region`: the operator-declared `--region` (`None` or exactly two ASCII
  uppercase letters). It is never inferred.

Ready requires all three boolean checks and a valid region; anything else is
`offline` with no region. Missing, unreadable or malformed inputs fail closed.
The observer keeps running and writes one bounded JSON object per diagnostic to
stderr using schema `secure-research-diagnostic/v1`. Events include
`interface_down`, `interface_flags_unreadable`, `route_dump_unavailable`,
`no_default_route` and `firewall_marker_insecure`; records never contain input
data, paths, interface names or regions. The lease is renewed every
`--refresh-seconds` (1–5, default 5) with an independent ten-second lifetime. On
`SIGTERM`/`SIGINT` it publishes `offline` before exit.

The observed generation stays stable while the exit is continuously Ready with the
same region. A fresh UUID is minted on every transition into Ready, on any region
change and after a restart, so an old browser session is never revived.

**Honest limitation.** The observer proves interface-up, an IPv4 default route on
that interface, a firewall marker and the operator-declared region. It does **not**
prove the cryptographic exit identity of the encrypted tunnel, the tunnel
peer/cipher, the actual firewall rules, or an IPv6 default route; IPv6 proof is
delegated to the kernel firewall invariant, which remains the independent
guarantee even if the observer and controller both fail. Treat the region as an
operator assertion, not as observed exit identity.

## Controller lifecycle

The future unit invokes, with directories created securely by the module:

```text
research-egress-control --input /run/research-vpn/observation.json \
  --output /run/agent-research-egress/control/state.json --drain-seconds 60
```

Input and output must differ. One controller exclusively locks `controller.lock`
in the output directory; this filename is reserved and must never be unlinked
while a controller runs. The lock, output and directory belong to root. The
published file has mode 0644 and contains no queries, credentials or exit address.
Service identities receive read-only directory projections in deployment.

Every 250 ms the controller reads the observation and atomically publishes a
complete lease, with expiry no later than either the input expiry or three
seconds ahead. Readers must observe directory replacements: bind the directory,
not an individual lease inode. No durable Ready state is restored after reboot.

Ready refreshes preserve the controller's generation. Exit changes, recovery
after offline and controller restarts generate fresh UUIDs, interrupting old jobs
and browser sessions. A matching drain preserves the generation for at most the
configured 1–300 seconds (default 60), measured with a monotonic clock. Repeated
drain heartbeats cannot reset that deadline. Draining without a matching prior
Ready state stays offline. Ready after an expired drain starts a new generation.

Startup first publishes offline. SIGTERM/SIGINT publishes offline before exit;
SIGKILL, I/O failure or a stalled controller leaves at most its last short lease.
Consumer polling adds its own observation latency. Wall-clock leases are not a
substitute for the independent kernel firewall invariant. Diagnostics contain
fixed error codes, not input data or filesystem paths.

## Evidence

Seven unit tests cover generation transitions, invalid/short input, bounded
draining, atomic replacement and unsafe ancestors. `scripts/check egress-control`
runs the actual binary as root **inside a private user namespace**, with isolated
mount/PID/network namespaces, exact runtime library roots and synthetic proof.
It checks locking, root-owned publication, file permissions/symlinks, transitions,
SIGTERM and crash expiry. This is not evidence for host VPN detection, firewall
rules, systemd deployment or packet confinement. See [development.md](development.md)
for reproducible commands and [verification.md](verification.md) for open gates.

Five unit tests cover the observer state machine: ready/offline, each failed
check, invalid regions, generation rotation on region change, recovery and
restart, and the refresh bound. Seven further unit tests cover the netlink
route-dump parser, including a default route found in a policy-routing table.
`scripts/check vpn-observer` runs the actual observer binary as root **inside a
private user namespace** against synthetic `--sysfs`/`--route-dump` inputs, a
synthetic marker and a temporary output directory. It checks publication,
region, locking, fail-closed transitions, `SIGTERM` shutdown and restart. This
is not evidence for a real VPN, real interface flags, real route tables, real
firewall rules or systemd deployment; the fixture never inspects host
networking.
