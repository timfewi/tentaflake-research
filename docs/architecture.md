# Architecture and evidence boundaries

The service consists of a stdio MCP client, a shared Unix-socket supervisor,
a protected egress proxy and isolated parser/browser workers. The NixOS module
provides their identity, filesystem, network and resource boundaries. Consult
[the verification matrix](verification.md) for current-source evidence and limits.

## Authority and content

The stdio client and service share request schemas and the versioned Unix
protocol. Provider adapters and execution backends belong to the optional
`service` Cargo feature; the standalone client is a transport adapter with no
provider credentials or HTTP/browser stack. The public five-tool contract does
not include domain-specific lead/contact enrichment. New adapters must retain
explicit grants and the existing budget, evidence and protected-egress boundary.

Only five research operations cross the agent socket. A source URL, title,
snippet, HTML node or PDF string never becomes executable configuration, a file
path, credential name, shell command or additional capability. Machine failures
use fixed service-authored codes. Source text remains explicitly untrusted.

`PublicUrl` validates schemes, ports, credentials and literal destinations.
`research-egress` resolves A and AAAA separately using explicit resolvers on
port 53 with Hickory 0.26.1. Only the Tokio feature is enabled; system resolver
configuration and DNSSEC support are disabled. Resolver-side answer filtering
is disabled so the public-address policy can reject the complete answer set. It
rejects a bad answer in either family before connecting to a numeric address.
A failed family cannot hide behind the other's success. Local interface addresses
are also denied and TCP sockets bind to the configured VPN interface.

These process checks do not replace the pending OS boundary: the service and
browser must have no direct route, while a dedicated egress-UID firewall must
enforce the VPN even during the host's direct-connection exception. DNS requires
the same firewall protection. The implemented [root lease controller](egress-control.md)
publishes bounded readiness leases and fresh generations after exit changes,
outages and restarts. Its trusted host VPN/firewall observation adapter and NixOS
units remain to be implemented and verified. The egress proxy
rejects expired leases, stops admission while draining and interrupts connections
on an offline state or generation change.

## Admission and evidence

The service configuration's `egress_uid` is the explicitly expected Unix socket
**listener peer** UID. It is not necessarily the proxy process UID: systemd
creates the activation listener as root, and Linux retains that identity in
SO_PEERCRED after passing the descriptor to the unprivileged egress process.
The NixOS module therefore emits `egress_uid = 0`, while `egressUid` still sets
the nonroot process identity and firewall rules. Missing/null peer configuration
is invalid. The relay checks exactly that configured peer; no root-or-any-user
fallback is allowed. Root-owned socket directories and restricted socket modes
remain part of the deployment boundary.

The worker-launching supervisor cannot inherit locked submounts beneath `/proc`:
the kernel then refuses bubblewrap's new procfs in its independent PID namespace.
The deployed fixture reproduced this with ProtectKernelTunables and
ProtectHostname=yes. Only the supervisor disables the first and selects
ProtectHostname=private with an explicit sethostname/setdomainname syscall filter.
Private UTS semantics are documented in the pinned
[systemd 261.2 manual](https://github.com/systemd/systemd/blob/v261.2/man/systemd.exec.xml).
Root-owned kernel controls remain unwritable to the nonroot/no-capability
supervisor; the VM checks actual write-open refusals without writing. Process
hiding, all worker namespaces, Chromium's sandbox and the other service guards
remain enabled. Egress/controller do not need this proc-mount exception.

SQLite reservations commit before each HTTP attempt. Concurrent clients share
job and UTC-day caps. Cancellation or uncertain billing preserves the cost hold;
startup recovery cannot create free spending capacity. Byte reservations include
the one-byte look-ahead needed to detect oversized decoded HTTP bodies.

Jobs belong to the Unix peer UID and the creating connection. Disconnect cancels
that connection's jobs; request cancellation only cancels that call. Each job
has a monotonic deadline and operation leases. Closing stops admission, cancels
the job and awaits those leases before deleting temporary evidence. A waiting
cache consumer can cancel independently of another job's initializer. Shared-UID
clients are one trust domain, not separate authenticated principals.

The socket reader retains partial frames across operation completion. A stalled
frame body has a timeout; IDs increase monotonically and calls have bounded
queues. MCP cancellation, including a dropped adapter future, sends an explicit
RPC cancel request. The service still joins the work before releasing its leases.

The content-addressed archive stores immutable source/representation IDs,
provenance, hashes and extraction versions. The HTTP entity after decompression,
rendered DOM and derived text are separate representations. Text chunks count
Unicode scalar values and report line locations. Binary chunks use base64 and
byte offsets. Reads verify hashes; eviction creates bounded ID-only tombstones.
The quota counts unique blob bytes and serialized source metadata. SQLite page,
index and filesystem overhead require additional deployment disk headroom.

Practical sources use a durable archive. Strict-mode content and provider results
without storage rights use job-owned temporary archives. Minimal budget data
survives both. Large responses have a bounded five-minute report with exact JSON
chunk continuation; closing its active job removes that report. Link previews
are short, but a separate saved links representation retains complete extracted
labels and URLs. Failed parsing leaves the earlier raw response accessible.

## HTTP and robots

Reqwest uses an explicit private TCP-to-Unix proxy relay because its direct Unix
transport ignores proxy configuration. Automatic redirects and retries are
disabled: each attempt must pass policy and admission again. Headers and upstream
diagnostics do not become public logs. Plain HTTP proxy forwarding strips
credentials and permits one bounded GET/HEAD or reviewed POST request per
connection. The browser request gate rechecks operator POST rules before using
that transport; a POST is never replayed automatically after an uncertain result.

TLS uses the Cargo-pinned Mozilla roots from `webpki-roots`, with normal
certificate/hostname checks and no client identity. Host trust stores and
certificate environment variables are not imported. Root updates require a
dependency update and rebuild. This also allows startup in an isolated root
without the host's `/etc/ssl` directory.

Robots matching uses explicit product groups, combines matching groups and uses
the wildcard only when no explicit group exists. The matcher has a CPU bound and
handles encoded paths, wildcards and end anchors. Network/5xx failures may produce
a warning for a selected page; discovery pauses and valid disallows remain
binding. The matching reference is [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html).

Bounded crawling is an option on `research_fetch`, not a sixth tool. The seed is a
normal selected-page fetch; discovered pages are followed only within the seed
origin, breadth-first, under client bounds clamped to operator `crawl_pages` and
`crawl_depth`. Every discovered page reuses the normal fetch path (redirects,
robots, budgets, document cache and immutable evidence), so it has its own source
identity. Discovery robots semantics are stricter than a selected page: a
disallow skips one page, while an unavailable/throttled robots document or an
exhausted budget pauses discovery and returns the seed plus already-fetched pages
with an explicit `crawl` summary and partial coverage.

## Parser supervision

The worker launcher creates fresh mount, PID, user and network namespaces through
Bubblewrap. It projects only the current input, output and enumerated Nix runtime
closure. It clears environment credentials and applies process memory, CPU,
file-size, descriptor and core-dump limits. The parent bounds result reads and
rejects output symlinks. Timeout/cancellation kills and reaps the namespace owner;
the integration test observes and checks a nested process as well.

Parser `/tmp` is a private scratch directory on the supervisor's temporary
filesystem, as with browser scratch. Both launchers also bind `/dev/shm` to that
scratch backing and remount the auxiliary root and `/dev` read-only (without
recursively making writable scratch/output submounts read-only). Device nodes stay
usable. This closes a reproduced regular-file write outside supervised scratch.
It is not proof of the aggregate 512 MiB cap: the deployment mount, cgroups and
adversarial nested namespace/mount behavior still require their own checks.

HTML extraction preserves text-node Unicode. Optional Readability text gets
its own representation/version. A first isolated Poppler inspection returns the
page count; an atomic page reservation precedes the text-extraction worker. Poppler returns
page-separated text; encrypted, empty-text, corrupt and excessive-page documents
have explicit outcomes. When every page is empty, an operator-enabled OCR phase
runs entirely inside the same isolated worker: `pdftoppm` rasterizes up to the
configured page cap, then `tesseract` recognizes each page from stdout. It is
offline and local-only — no network, provider or LLM — and so remains available
under strict privacy. PDF page order is preserved (each derived `PdfPageText`
representation keeps its page number), the extraction version identifies the
phase and languages (`ocr/<languages>/v1`), and a warning marks the derived
text. The phase is bounded by page count, DPI, a per-command timeout, total
recognized bytes and the worker's existing RLIMIT_CPU/AS/FSIZE. If OCR yields no
text the document still fails with `OcrRequired`; text is never fabricated.
With OCR disabled (the default) the previous `OcrRequired` behavior is
unchanged. Chromium sandbox and browser-specific lifecycle evidence
are separate work and cannot be inferred from parser tests.

## Optional summarization

Summarization is the one place retrieved content leaves the host for analysis,
and it is deliberately separate from retrieval: `research_read` `kind:
"summary"` is the only entry point, nothing in search, fetch, rendering or
crawling ever calls it, and Research is complete without it. The service — not a
worker or the adapter — selects the saved text representation, verifies it
against its stored hash, cuts it at `limits.summary_input_bytes` on a character
boundary, and hands the bounded text to the `SummarizeProvider` behind the
operator's `summarize` capability and `content` grant (`summarize_order`, never
under strict privacy). The adapter sends a fixed instruction frame that labels
the text as untrusted data plus the text itself; no caller prompt exists. The
provider's exact JSON and the generated text are archived as a **new source**
with distinct representations, so a summary can never be mistaken for, or
overwrite, the evidence it was derived from. The operator's `request_micro_usd`
is a per-request ceiling reserved atomically like any provider charge and settled
in full on success; the input/output bounds make that ceiling computable.
Summaries are generated data: the result says `generated: true` and quotes must
still be read from the original representation.

## Browser message resources

Each browser CDP connection retains at most 64 MiB of serialized queued commands
and 64 MiB of serialized responses awaiting consumers, in addition to its bounded
WebSocket buffers. Events are limited to 1 MiB each and 4 MiB in aggregate,
including events dequeued but still held by a consumer. Existing queue-count and
pending-request caps also apply. Response envelopes borrow raw JSON before typed
decoding, avoiding an intermediate generic object tree for large responses.
Overflow stops the session; it never drops arbitrary events and continues with
incomplete policy state. These are serialized-payload limits, not a claim about
total process memory; the 2 GiB aggregate deployment cgroup remains required.

The internal [resource fragment](resource-boundary.md) now specifies the shared
cgroup and service scratch mount. Its configuration and generated-unit syntax
pass; full-module integration and runtime enforcement remain unverified.
