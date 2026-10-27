# Operations

Import the flake's `nixosModules.default`. The compatibility namespace remains
`services.secureResearch`; enabling it requires explicit service and egress UIDs,
client identities, a VPN interface and public DNS resolvers. Select UIDs that do
not collide with other host users or groups. The module asserts these boundaries.

```nix
services.secureResearch = {
  enable = true;
  serviceUid = 4201;
  egressUid = 4202;
  clients.research-client = 61001;
  vpnInterface = "wg0";
  resolvers = [ "9.9.9.9" ];
};
users.users.research-client = {
  uid = 61001;
  isSystemUser = true;
  group = "research-client";
  extraGroups = [ "agent-research-clients" ];
};
users.groups.research-client = { };
```

This fragment does not configure a VPN or authorize paid providers. The operator
must supply trusted VPN readiness observations. The root lease controller checks
their freshness and generations; without them the service fails closed. The
optional reference observer requires an operator-owned firewall readiness marker.
See [egress-control.md](egress-control.md) and [network-boundary.md](network-boundary.md).

Use `research_job` operation `readiness` through the intended client socket to
inspect the authorized caller UID, effective policy fingerprint and the lease
generation actually observed by the service. Compare it with the trusted
controller and authenticate the installed process/configuration before using it
for admission. `providers` reports configuration only. Neither operation probes
an upstream provider; [the API](api.md) defines the snapshot and expiry semantics.

Provider keys stay in runtime credential files. Enabling a provider additionally
requires explicit capability/data grants and a cost ceiling; a key grants nothing
on its own. Research summarization stays off in the standard Tentaflake topology,
whose LLM requests use their own broker. Review [providers.md](providers.md) before
enabling optional cloud adapters.

The socket at `/run/agent-research/socket` is local and peer-UID authorized. Grant
the socket group only to permitted client sessions. Deny direct networking for
clients as well as disabling native web tools. A Unix socket mount is a capability:
project only the intended socket directory, never credentials, the host root or
unrelated service sockets.

For OCI clients declare `services.secureResearch.containerClients.NAME.uid` with
a distinct host UID for every agent. Project only
that relay's socket and the client's exact runtime closure into the container.
Its host socket is `/run/tentaflake-research/NAME/socket`. The root-only parent
protects each socket capability; only its selected child directory is projected.
The relay forwards through AF_UNIX with no IP networking. Shared internal
container UIDs then do not merge job ownership at the research service. Each
relay permits four connections and shares the aggregate research slice limits.
Healthy stdio sessions may remain connected between tool calls; frontend MCP pings
need not traverse the internal RPC. If the upstream session closes, a new tool call
can reconnect using five bounded attempts with backoff. Interrupted calls report
`cancelled` without replaying their operations; explicit client close stays final.
Stopping a relay socket terminates its accepted
relay instances. Stopping the upstream socket also stops the client sockets. The
socket must be stopped to revoke admission; stopping only the socket-activated
service allows a new connection to start it again. The container-client VM exercises
cross-job refusal, a 65-second idle gap, live socket revocation and recovery after
a service crash without restarting the stdio client.

Practical mode archives evidence with bounded retention; strict mode uses ephemeral
job content. Budget/accounting data remains persistent. Allocate disk headroom
beyond the content quota for SQLite/filesystem metadata and monitor failures.
The research slice caps aggregate memory/tasks and scratch; see
[resource-boundary.md](resource-boundary.md).

## Guarded paid ledger

The guarded ledger is opt-in; existing deployments default to unguarded
initialization. **NixOS guarded admission is currently blocked by an assertion.**
A read-only bind mount can retain an old marker or state directory after the
host path is replaced, and the root pre-start check cannot detect a later change.
The proposed continuous host witness remains subject to security review and
host acceptance; do not bypass the assertion or widen mounts.

The proposed witness has its own explicitly configured, distinct non-root
`guardedLedger.witnessUid`/GID, no capabilities, no provider credentials and
fixed marker and state paths. Systemd creates its root-owned Unix listening
socket; only that socket and the root-owned marker directory are projected
read-only to the Research service. For each guarded check the service opens a
new connection, checks the kernel peer UID is root, sends a new random challenge
and requires it in the bounded reply within a two-second deadline. The witness
accepts only the configured service UID, reopens both paths' host-controlled
ancestors without following symlinks, and checks the original ancestry, marker,
lock and bounded marker contents. From the verified parent it stats, without
opening, the service-owned `0700` state directory. The service compares the
observed device, inode, owner and mode to its pinned state directory and checks
the database and journal inside it. A mismatch or witness restart fails closed.

Guarded ledger access is serialized. New admission or status work may receive
`capacity` under contention rather than blocking a second service runtime
worker. Already-dispatched receipt settlements and job cleanup use bounded
serialized accounting, and cleanup waits for accounting rather than treating
contention as completion. Filesystem and SQLite operations cannot necessarily
be interrupted; if durable settlement fails, the reservation remains held and
the job requires reconciliation.
An accounting worker failure blocks admission and terminal success while
preserving held costs. Browser, cache, ephemeral evidence and report cleanup
must still be attempted independently of that accounting failure.

The witness intentionally has no private mount namespace: one can pin an old
mount and conceal a replacement. Its dedicated identity relies on host DAC to
prevent access to private files; credentials must not be world-readable. Before
any admission can be considered, independently establish that the actual unit
and host defaults leave it in the host mount namespace, that the root-created
socket passed to the distinct witness UID reports root peer credentials, and that
the effective sandbox and identity are safe. Nix checks declared identity
collisions, not occupants of the live host: the operator must separately verify
the chosen UID/GID is unused and dedicated. Current source fixtures do not
establish those deployment properties. Root remains trusted, and an operator
mutation concurrent with or immediately after a check is not prevented atomically.

The default marker is `/var/lib/agent-research-guard/budget.marker`; it is
non-secret, on persistent storage, and would be projected read-only into the
service. Its directory and every ancestor must be real root-owned directories
without group/other write permission. The marker must be a root-owned regular
file without group/other write permission and cannot be a symlink or hard link.
The marker and directory must never be writable by the service identity.

Provisioning is a separately authorized root operation, not part of startup,
activation or this repository's tests. Before the one-time operation, stop and
disable activation through the Research service **and socket**, and ensure the
state directory `/var/lib/agent-research` exists as a real directory owned by
the configured `agent-research` UID/GID with mode `0700`. Create the separate
root-owned marker directory with mode `0755`. Every ancestor must be root-owned
and not writable by group or other users. With the reviewed service binary:

```sh
/path/to/research-service --provision-ledger \
  --state-directory /var/lib/agent-research \
  --ledger-marker /var/lib/agent-research-guard/budget.marker
```

Use a different `--ledger-marker` if `guardedLedger.markerPath` was explicitly
configured. Provisioning creates and syncs the root-owned `ledger.lock` in the
marker directory; the service and provisioner take their exclusive flock on
this protected, service-read-only file. The marker binds its inode, and every
guarded admission checks the still-held lock and its pathname. A missing lock
after marker publication is not recreated by another provisioning attempt. The
marker cannot be named `ledger.lock`.
The guarded service also takes the original state-directory `service.lock` so
that an already-running ordinary unguarded instance cannot overlap it. Unlike
the protected lock, that legacy file is service-writable and is not itself an
anti-replacement authority. Stop all old instances before provisioning.
Provisioning refuses an existing marker, database, rollback journal, WAL or
shared-memory sidecar; it never migrates, overwrites or resets an existing
ledger. It syncs the database, journal and directory before publishing and
syncing the marker. If provisioning is interrupted, do not simply delete partial
files or rerun it: stop admission and have the operator inspect and reconcile the
state under separately authorized recovery procedures. Existing unguarded
ledgers are not automatically migrated or reset.

Guarded ledgers use SQLite `TRUNCATE` rollback-journal mode rather than WAL.
Their identity, database inode and persistent journal inode must match the marker.
After each committed write, the journal contains a zero SQLite header and a
sentinel binding the ledger identity, transactionally incremented database
generation and last-observed clock value; it is synced before admission
continues. Restoring only an older database is rejected if its inode, marker
and journal remain unchanged.
A missing, replaced or corrupt database or journal, marker-content change,
unexpected WAL/shared-memory file, WAL-mode database header, inconsistent
accounting or mismatched generation stops admission. Even an apparently
recoverable hot journal is treated as ambiguous; do not remove it to restart.
Committed reservations are synced before dispatch; on restart valid reservations
remain held and interrupted work is closed. Guarded admission checks the clock
before transaction writes, so a rejected backward clock can recover when time
catches up. A crash or storage error after a write begins can leave an ambiguous
journal or sentinel and requires operator reconciliation; do not reconstruct it
automatically. Unknown costs continue to count against the current daily cap,
including holds recorded on earlier UTC dates.

The sentinel is service-writable and is not an authenticated database digest.
A privileged or service-UID writer able to rewrite a coherent database and
sentinel can defeat this guard; coordinated database/journal rollback is likewise
undetectable. A local ceiling is not an invoice guarantee. Before paid dispatch,
independently verify provider pricing and maximum request charges, or configure
provider-enforced hard caps covering the actual account; otherwise keep paid
dispatch disabled.

Stopping egress/firewall/VPN readiness must prevent new public requests. Preserve
the fail-closed unit dependencies when integrating with other service managers.
Validate actual packets and worker file access on the intended deployment before
treating it as production-ready.
