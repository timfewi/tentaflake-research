# Deployment resource-boundary component

`nix/resource-boundary.nix` is an internal fragment, not a deployable service.
It takes `lib` and a non-root numeric `serviceUid`; the complete module must assign
that exact UID to `agent-research`.

The service, `agent-research-egress` and `agent-research-egress-control` share
`agent-research.slice`: 2 GiB memory, zero swap and 1024 tasks (including threads
and descendants), with accounting enabled. Units disable delegation and core
dumps, use control-group shutdown with a 30-second SIGKILL deadline, stop on OOM,
limit descriptors to 4096 and use umask 0077.

Only the service gets a writable temporary filesystem: 512 MiB at `/tmp`, owned
by the service UID, mode 0700, nosuid/nodev/noexec. Workers bind scratch/output
and shared memory from this backing rather than allocating per-worker tmpfs;
strict evidence also originates there. `PrivateTmp=false` avoids a second
temporary allocation. `/var/tmp` and outer `/dev/shm` are inaccessible; workers
create their private device view and bind supervised shared memory. Egress and
controller have no writable `/tmp`, `/var/tmp` or `/dev/shm`; controller atomic
leases use a separately projected runtime directory.

This does not yet prove aggregate enforcement. The complete module must restrict
all other filesystem projections and cgroup escape, and test nested mounts
without disabling Chromium's sandbox. Runtime OOM, task exhaustion, ENOSPC,
restart and forced-descendant cleanup require an isolated deployment fixture.
Archive retention is separate from transient storage.

## Evidence and reproduction

`checks.x86_64-linux.resource-boundary` combines the resource/network fragments
in synthetic NixOS configuration. Seventeen checks cover UIDs, shared slice,
limits, stop policy, cores, temporary allocation/alternatives and preserved
firewall dependencies. Generated service/slice units pass the pinned systemd
parser in user-manager verification mode, with scratch inside the build sandbox
and discovery restricted to generated and immutable package units. This is
syntax evidence, not system-manager activation or enforcement. No host units or
journal are read. Initial parser failures exposed missing fixture runtime/unit
paths; both are now supplied explicitly without touching host `/run`.

```bash
nix build --offline --no-write-lock-file --no-link --print-out-paths \
  path:.#checks.x86_64-linux.resource-boundary
```

Next assemble this and the [network fragment](network-boundary.md) with exact
runtime-closure projections, sockets, credentials and the trusted readiness
adapter into `nixosModules.default`. Their checks do not accept full deployment.
