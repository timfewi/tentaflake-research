# Verification evidence

This repository is experimental. The following gates are independent. Each row below names a current-source local run. All upstreams and credentials
in these fixtures are synthetic.

| Boundary | Check | Current evidence |
| --- | --- | --- |
| Rust policy, budgets, ownership, protocols | `project-check fast` | Passed locally, 2026-10-01 |
| Pinned packaged service/client/egress | `project-check full` | Passed locally, 2026-10-01 |
| NixOS options, nftables syntax, aggregate resources | `module`, `network-boundary`, `resource-boundary` | Passed locally, 2026-10-01 |
| Real deployed service and stdio MCP | `credentials-vm`, `resources-vm` | Passed locally with real stdio MCP, 2026-10-01 |
| Firewall direct-path denial | `network-boundary-wireguard-vm` | Passed locally; also denies the direct physical path, 2026-10-01 |
| Real encrypted VPN and tunnel loss | `network-boundary-wireguard-vm` | Passed locally, 2026-10-01 |
| Credential and scratch isolation | `credentials-vm`, `parser-credentials-vm` | Passed locally, 2026-10-01 |
| Browser namespace and rendering | `rendering-vm` | Passed locally, 2026-10-01 |
| Aggregate memory, process and scratch limits | `resources-vm` | Passed locally, 2026-10-01 |
| Per-container identity and source isolation | `container-clients-vm` | Passed locally, 2026-10-01 |
| Actual Hermes/ZeroClaw agent use | Tentaflake integration fixture | Pending integration/run |

Live paid-provider billing, a production operator's VPN/firewall, arbitrary kernel
or nested-mount escapes and ARM compatibility have not been accepted. The synthetic
tests do not require real API keys. No production host has been activated by this
extraction.

The source fast gate passed 269 Rust tests plus formatting, Clippy, Nix lints and
ShellCheck. All three package outputs and configuration gates passed. Six VM
checks passed: container identities, WireGuard, resources, credentials, rendering
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
