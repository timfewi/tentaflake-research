# Verification evidence

This repository is experimental. The following gates are independent. Evidence
below distinguishes the extraction baseline from later focused reruns. All
upstreams and credentials in these fixtures are synthetic.

| Boundary | Check | Latest recorded evidence |
| --- | --- | --- |
| Rust policy, budgets, ownership, protocols | `project-check fast` | Passed on client-recovery source, 2026-10-01 |
| Pinned packaged service/client/egress | `project-check full` | Passed on client-recovery source, 2026-10-01 |
| NixOS options, nftables syntax, aggregate resources | `module`, `network-boundary`, `resource-boundary` | Passed on client-recovery source, 2026-10-01 |
| Real deployed service and stdio MCP | `credentials-vm`, `resources-vm` | Extraction baseline passed with real stdio MCP, 2026-10-01 |
| Firewall direct-path denial | `network-boundary-wireguard-vm` | Extraction baseline passed, including direct physical path denial, 2026-10-01 |
| Real encrypted VPN and tunnel loss | `network-boundary-wireguard-vm` | Extraction baseline passed, 2026-10-01 |
| Credential and scratch isolation | `credentials-vm`, `parser-credentials-vm` | Extraction baseline passed, 2026-10-01 |
| Browser namespace and rendering | `rendering-vm` | Extraction baseline passed, 2026-10-01 |
| Aggregate memory, process and scratch limits | `resources-vm` | Extraction baseline passed, 2026-10-01 |
| Per-container identity and source isolation | `container-clients-vm` | Passed on client-recovery source, 2026-10-01 |
| Actual Hermes/ZeroClaw agent use | Tentaflake integration fixture | Pending integration/run |

Live paid-provider billing, a production operator's VPN/firewall, arbitrary kernel
or nested-mount escapes and ARM compatibility have not been accepted. The synthetic
tests do not require real API keys. No production host has been activated by this
extraction.

The extraction baseline (`6536617`) passed 269 Rust tests plus formatting,
Clippy, Nix lints and ShellCheck. Its three package outputs and configuration
gates passed. Six baseline VM checks passed: container identities, WireGuard, resources, credentials, rendering
and parser credentials. The relay fixture first found a missing `/sys` mount
target; the minimal root now supplies it without exposing host files.

The redacted Gitleaks scan found no leaks in the extracted source; OSV found no
known advisories in the 330-package Cargo lockfile. These are time-bounded scans,
not a guarantee that all credentials or vulnerabilities can be detected.

Relay lifecycle regression: a 65-second gap between initialization and a tool
call reproduced the old transport timeout. Relays now retain healthy sessions;
connection counts, memory, processes, IPC frames and job budgets remain bounded.
The socket-stop fixture checks revocation of already accepted instances. The current-source
fast gate and real VM fixture passed on 2026-10-01, including the 65-second gap
and revocation while an accepted relay is running.

Persistent-client recovery: the packaged stdio adapter first reproduced a
permanent `cancelled` response after its Unix RPC session was lost. The new
regression verifies that a later undispatched call opens a fresh session,
without replaying a dispatched operation. Cancellation during reconnection and
explicit client close also remain final for the affected call or client.

For this client-only follow-up, `project-check fast`, `project-check full`, and
`container-clients-vm` passed locally on 2026-10-01. The VM completed in 83.08
seconds, including the 65-second idle interval, live socket revocation, and a
real service SIGKILL followed by a successful new call from the same stdio
process (4.39 seconds). The other five VM fixtures retain their baseline
results and were not rerun for this change. The current-source redacted
Gitleaks directory scan found no leaks; the Cargo lockfile is unchanged.
