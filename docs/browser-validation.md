# Browser validation checkpoint

This records project defects and synthetic test evidence only. It intentionally
contains no device identifiers, host journal excerpts, process identifiers or
personal configuration.

## Startup defects

The investigated crash records identified three failures resolving the packaged
sandbox helper and two failures in Skia's font-family enumeration. The sixth
record had no stack trace establishing its cause. No further host inspection was
performed after the user's privacy restriction.

The private worker environment now explicitly supplies the packaged sandbox
helper and a pinned fontconfig containing DejaVu and emoji fonts. The real
rendering fixture starts with Chromium's sandbox enabled and verifies additional
renderer seccomp filters and no-new-privileges.

Chromiumoxide 0.9.1's `ArgsBuilder` prefixes argument keys with `--`. Passing
already-prefixed keys produced `----` switches, so the intended proxy and network
switches were ineffective. The launcher now supplies bare keys and explicit
key/value pairs. The regression reads the launched test process's arguments,
rejects duplicate/four-hyphen switches and requires the actual proxy, bypass,
resolver, QUIC, WebRTC and background-networking options. Component extensions
with background pages are disabled explicitly.

Earlier rendering tests did not verify effective Chromium switches. Their
passing result must not be used as evidence for those options or for historical
absence of network traffic.

## Observed local isolation

The real Bubblewrap/Chromium fixture verifies:

- A network namespace distinct from the test parent, with only a loopback
  interface; the Chromium process belongs to that private namespace.
- Without Fetch interception, both a public navigation and a loopback navigation
  fail with `ERR_PROXY_CONNECTION_FAILED`. A listening synthetic loopback server
  receives no connection, detecting Chromium's usual implicit proxy bypass.
- Host-loopback and host-file canaries are inaccessible; the worker has no
  supplied host credential environment and response storage is read-only.
- Intercepted public HTML and JavaScript requests still render exact Unicode.
- A cross-site iframe is configured before resumption; its public subrequest
  reaches the checked fixture broker.
- An additional page is denied script execution and all URL requests before its
  startup pause is released for closing. Closing while still paused otherwise
  deadlocked the opener. No popup request reaches the broker.
- Dedicated workers cannot be closed individually with Chromium's `CloseTarget`.
  Unsupported targets remain attached and paused with no broker authority and
  a finite target count. The fixture observes a paused worker, verifies its
  synthetic fetch never reaches the broker, and ends the entire browser.
- Configured screen/viewport dimensions, en-US, UTC and the unchanged actual
  Chromium user agent are observed in the page.
- The protected HTTP default User-Agent has the same Linux platform and reduced
  Chrome version as the real pinned Chromium, after removing Chromium's
  `Headless` token for HTTP fetches. The real browser fixture checks this on
  every pin update and observes the actual browser User-Agent at the request
  broker. It does not prove fingerprint resistance.
- Renderer descendants exit and the temporary profile is removed on close.
- Auxiliary root and `/dev` mounts reject regular-file writes; `/dev/shm`
  writes appear in supervised scratch. The worker receives EOF before the
  supervisor resorts to a hard kill, allowing bounded cooperative teardown.
  A synthetic worker separately proves EOF cleanup precedes broker drain and
  workspace deletion. Forced-kill namespace teardown and deployment-wide
  quotas still require adversarial deployment checks.
- Response bytes cross a read-only mounted directory; rendered HTML crosses a
  numeric output file plus a size-bounded metadata frame. The parent checks the
  declared size, hash and reference metadata before reading the result. Separate
  file tests reject symlinks, hardlinks, FIFOs and directory-path replacement.

The private worker binary now combines the target controller, reader and body
exchange over nonblocking pipes. Its stdin pipe is duplicated with close-on-exec
and fd 0 is replaced before Chromium starts. A separate real-process fixture
exercises all six actions, pending-request reporting, response acknowledgements,
disconnect during navigation, an infinite script stopped by the action deadline,
cancellation on document changes and cleanup of a response arriving after cancel.
It also loads a cross-origin image from a page that requests `unsafe-url` and
observes the full Chromium `Referer` before the broker reduces it to the source
origin. The shared request gate removes Referer on HTTPS-to-HTTP downgrades and
rejects `Origin` values that contain a path or query in focused regressions.
The plaintext egress proxy separately applies the same metadata policy to raw
HTTP requests from its authorized peer. The service HTTP transport applies it
before Reqwest sends HTTPS requests through an opaque CONNECT tunnel.
File-write tasks are retained and joined before acknowledging Close.

The parent supervisor now limits concurrent workers, rechecks request policy and
IPC metadata, validates returned HTML files and waits for worker/broker/file
cleanup before releasing capacity. A third real-process fixture covers startup
failure cleanup, HTTP
denial and recovery, navigation cancelling an old request, explicit cancellation,
dropped calls and sessions, job cancellation, idle expiration and workspace
cleanup. Error responses are acknowledged too, so cancellation crossing an
error-only reply cannot leave an ambiguous pending request.
A denied scratch removal now exercises the failure path: Close returns `storage`,
the pool permit stays held, and stderr contains only a fixed diagnostic event.
A second denied-removal case proves a worker startup error cannot hide a later
cleanup failure. A missing Bubblewrap executable checks pre-actor spawn failure
cleanup without leaving a workspace.

The production manager and HTTP/robots/archive broker now have a fourth fixture
using real service sockets and the actual stdio MCP binary. It verifies all six
actions, stale references, wrong-owner/job rejection, exact Unicode source reads,
separate raw/DOM/text identities, one-shot fetch cleanup, bounded/deduplicated
browser batches, automatic rendering and retained HTTP evidence on render failure.
Private targets/redirects, robots denial, robots-error warnings, parser failure,
action/document/byte exhaustion and the absence of fallback after HTTP policy or
access errors are exercised through the service.

The service/browser fixture now also exercises a granted cross-origin JSON read
POST. Its real Chromium worker sends OPTIONS first; the service checks and saves
the synthetic upstream CORS response, then admits only the reviewed POST body.
A separate denied-preflight run returns 403 and verifies that no POST follows.
The fixture uses a synthetic transport; the protected HTTP client and plaintext
proxy each have separate preflight checks.

A separate real browser/service run limits a job to two HTTP requests. Robots
and the main page consume them; Chromium attempts an image subrequest, which
the page reports as `budget_exceeded`. The ledger remains at two requests. This
uses a synthetic upstream and does not establish deployed packet enforcement.

The fixture reproduced a cleanup race: maintenance removed a closing session
before awaiting its broker, allowing concurrent job shutdown to delete strict
evidence before late archive writes. Closing sessions now remain discoverable
until cleanup completes. A held synthetic response proves job shutdown waits for
concurrent maintenance, joins late archive work and leaves no workspace or strict
evidence. Call/job cancellation, egress interruption, socket disconnect and MCP
stdio EOF also exercise cleanup. The upstream transport and parser in this
fixture are synthetic; protected HTTP and isolated parsing have separate tests.

These local tests do not establish deployed VPN-only routing, behavior during a
host direct-network exception, complete frame/worker coverage or native harness
integration. Those acceptance requirements remain open. Crash-content retention
also needs an explicit deployment policy; do not infer it from temporary profiles
or Chromium's crash-reporter switches.

## Coherent exit-region profiles (D2)

The trusted egress lease (`EgressState`) carries an optional `region`: the
observed VPN exit as an ISO 3166-1 alpha-2 code. The field is omitted or `null`
when the adapter cannot establish a region. Existing leases and observations
without it remain valid, and an invalid value (anything other than exactly two
ASCII uppercase letters) makes the whole lease invalid so a session never
selects a profile from an unvalidated region. The controller propagates the
observed region while the lease is Ready or a matching Draining and drops it
whenever the mode goes offline or the exit generation changes.

`BrowserConfig.profile` selects the policy (Nix `browser.profile`, default
`neutral`):

- `neutral` — always en-US / UTC / `en-US,en;q=0.9`; existing behavior.
- `exit_region` — a coherent profile from the observed region, or the neutral
  fallback when the region is absent or unknown. The fallback is itself
  internally coherent.

The mapping is a bounded, sorted, hand-reviewed table (27 countries) of
`region -> (locale, IANA timezone, Accept-Language)`, for example DE -> de-DE /
Europe/Berlin / `de-DE,de;q=0.9,en;q=0.8` and JP -> ja-JP / Asia/Tokyo /
`ja-JP,ja;q=0.9,en;q=0.8`. Every entry uses the region's own language, a real
IANA zone in that country and an Accept-Language whose primary tag matches the
locale. Unknown regions are never guessed; extending the table requires review.
Covered regions: AT, AU, BE, BR, CA, CH, CZ, DE, DK, ES, FI, FR, GB, IE, IN, IT,
JP, KR, MX, NL, NO, PL, PT, SE, SG, US, ZA.

A profile is captured once, when a browser session is created, and is fixed for
that session: the locale and Accept-Language become `--lang`/`--accept-lang`,
the timezone becomes the worker's `TZ`, and CDP locale/timezone overrides use the
same values. Rotation happens only *between* sessions — a running session is
never rewritten when the observed region later changes; only client-disconnected
or new sessions pick up a new region. The tool never chooses or changes the VPN
exit and promises no anonymity; it only adapts to the exit the trusted lease
reports.

Evidence: `browser::profile` unit tests cover the neutral profile, a coherent
German mapping, the unknown-region fallback, table coherence/sorting and
rejection of malformed strings; `egress_control` unit tests cover region
survival across a Ready refresh and a matching drain, dropping on offline/exit
change, and an invalid region failing closed; `browser::manager` captures a
session profile without mutating it when a later region is resolved. The
observation producer (`research-vpn-observer`) now exists; its deployed
encrypted-tunnel/packet acceptance remains open.

### Deployed isolated-VM evidence (2026-09-17)

`checks.x86_64-linux.rendering-vm` exercises the real MCP client through the
service, egress and isolated Chromium with `browser.profile = "exit_region"`.
The fixture's root-owned observation lease is **synthetic**: it deliberately
publishes a fixed `"region": "DE"` and this fixture does not detect a VPN exit.
The script-bearing page appends
`navigator.language + "|" + Intl.DateTimeFormat().resolvedOptions().timeZone +
"|" + navigator.languages.join(",")` to the rendered DOM, and the probe reads the
rendered source back through the real MCP browser read and asserts the exact
string `de-DE|Europe/Berlin|de-DE,de;q=0.9,en;q=0.8`. (The pinned Chromium
exposes the q-weighted Accept-Language tokens in `navigator.languages`, so the
observed language list starts with `de-DE`.) That is deployed evidence that the
region-derived, internally coherent profile (locale, IANA timezone,
Accept-Language) reaches the actual rendered Chromium session, not merely the
Rust configuration. The existing exact-Unicode and JavaScript-only rendered
additions are asserted in the same run and were not weakened.

This is **not** VPN exit proof and **not** a claim of anonymity: the region input
is a fixture constant, and the feature only adapts to whatever exit a trusted
lease reports. The neutral policy (`en-US` / `UTC`) is covered by the
`browser::profile` unit test rather than a second VM run, which would double the
boot and browser cost without adding deployed-path coverage.
