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


## Provider-independent client and extraction follow-up (2026-10-03)

Requirement: retain the public five-tool, per-UID/no-replay boundary while making
client builds independent, improving generic fetching and keeping provider
selection optional. No domain-specific enrichment interface is added.

Changed areas: `Cargo.toml`, shared API/protocol DTOs and feature gates;
`nix/package.nix`, flake apps and client packaging checks; synthetic client
process tests and the dependency guard; HTML worker/extraction warning mapping,
redirect-aware crawl visitation; neutral provider defaults and read-only
`research_job` operation `providers`; CI client feedback, Cargo caches and docs.
The controller, observer, egress firewall and public bridge recovery code are
unchanged. `UPSTREAM.md` records the selected source provenance.

Before fixing extraction, the new service regressions failed: a long-navigation
application shell had no JavaScript hint, and a redirected seed was fetched
again, exhausting the 16-request budget before the final discovered page. After
the fixes, both regressions pass; the crawl records one seed-destination fetch,
three discovered pages and 14 charged requests. Streamed content is derived
partial evidence, never observed browser placement, and no script is executed.

Current-source evidence:

- `project-check fast`: passed. Client-only checks run without service features;
  default-feature tests include 211 library tests and 58 service RPC tests.
  The existing reconnect, cancellation, ownership and conservative provider
  fallback regressions still pass. New provider inspection tests prove offline
  availability with full job capacity, authorization, no network or charges,
  secret-free output and strict-privacy filtering.
- Focused Nix builds of `research-client`, `checks.x86_64-linux.module` and
  `checks.x86_64-linux.parser-tools`: passed. The actual narrow client source
  package builds and tests its two binaries without service dependencies.
- `scripts/check worker-isolation`: passed using the pinned Bubblewrap/Poppler
  paths and parser closure. Actual isolated worker coverage includes streamed
  Unicode, hidden-content exclusion, shell/challenge handling, HTML/PDF/OCR,
  private mount/network namespaces, credential isolation and abort/timeout cleanup.
- `actionlint` 1.7.12: passed on the updated workflow. GitHub execution and a
  measured CI speedup remain unverified.

Full service package rebuilds, browser/runtime VM suites, production VPN checks,
paid provider calls and host activation were not run for this follow-up. Existing
VM evidence above remains historical. The standard fast gate's generic Semgrep
baseline scanned no Rust files and is not Rust security evidence.

Publication checkpoint: the DCO-signed source is pushed for review in
[PR #3](https://github.com/timfewi/tentaflake-research/pull/3). The staged redacted
Gitleaks scan passed. After upstream review/merge, the consuming input update and
affected deployment fixtures are tracked in
[Tentaflake issue #110](https://github.com/timfewi/tentaflake/issues/110).
Provider-independent VPN adapter acceptance remains separate in
[issue #4](https://github.com/timfewi/tentaflake-research/issues/4).
The template still pins its previously published Research revision; no lockfile,
private runtime catalogue, host state or real credential was copied.
