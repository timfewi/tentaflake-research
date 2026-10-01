# Tool and socket contract

The client invocation is `research-client --socket /run/agent-research/socket`.
The service invocation is:

```sh
research-service --listen-fd 3 --temporary-directory /tmp/research \
  --public-only --config /etc/research/config.json
```

The service requires the operator's existing internal egress socket, even while
the VPN is offline. It adopts the listening Unix stream socket before starting
runtime threads, validates `LISTEN_PID`, `LISTEN_FDS=1`, path, mode and owner, and
rejects alternate-FD extensions. Direct startup without activation is an error.
Only MCP JSON goes to client stdout. Egress-path diagnostics are bounded JSONL
records on stderr under schema `secure-research-diagnostic/v1`; they use only
service-authored categorical fields and never include tool input or source data.

## Five operations

| Tool | Arguments | Result |
| --- | --- | --- |
| `research_job` | `operation`: `start`, `status`, `finish`, `cancel`; `job_id` except for start; optional reduced `limits` on start | Job state, limits, usage, remaining budgets, granted capabilities and available source IDs |
| `research_search` | `job_id`, `queries`: objects with `q`, optional `count`, `language`, `country`, `freshness` | Per-query state, snippets, source, provider, cache hit, coverage and usage |
| `research_fetch` | `job_id`, `urls`, optional `mode`: `auto`, `http`, `browser`, `provider`; optional `crawl` (`pages`, `depth`) with `http`/`auto` | Per-URL state, source, raw-source ID, link preview, complete links representation, extraction error, JavaScript need and an optional bounded-crawl summary |
| `research_browser` | `action`: `open`, `read`, `follow_link`, `expand`, `scroll`, `close`, with job/session/versioned reference as applicable | Session ID, observed page/references, DOM and text sources, cumulative HTTP receipts, partial/error state |
| `research_read` | `kind`: `metadata`, `source`, `pdf_page`, `report`; optional expansion `summary` (below) | Saved metadata or exact bounded evidence/report chunk; summaries retain separate evidence |

Per-call maxima are 16 search queries and 64 fetch URLs, further reduced by the
operator's job limits (defaults: 8 queries and 20 documents). This bounds result
assembly independently of a larger operator-configured lifetime job limit.
Identical batch inputs share work and retain their original indexes with
`duplicate_of`. Coverage separately counts success, empty, partial, failed and
skipped items. A failed query alongside an empty query is not complete emptiness.

`research_search` follows the configured `search_order` (SearXNG, Brave, Tavily): the first
granted provider is preferred, and only unambiguous failures (unavailable,
authentication, rate limit, invalid response) fall through to the next. Uncertain
charges, policy/access blocks and budget limits are never replayed across
providers. The result names the provider that answered.

Start example:

```json
{"operation":"start","limits":{"seconds":120,"micro_usd":100000}}
```

The returned ID is `job.id`; counters are in `job.usage`, and caps in
`job.limits`. Top-level `remaining` subtracts used and reserved capacity,
including uncertain money holds. Its `seconds` is time until the deadline.
Remaining capacity does not reopen a finished job or override the independent
UTC-day spending cap. Search attempts consume query slots; summaries consume
requests, bytes, time and money without consuming extra search slots. Cache hits
do not incur another upstream charge.

Top-level `capabilities` lists installed adapters with effective operator grants,
filtered by privacy, under `search`, `scrape` and `summarize`.
Each entry has `provider`, `request_micro_usd` (the configured reservation ceiling,
not a live tariff) and `storage` (`job` or `persistent`). The object also includes
`privacy`, `http` and `browser`. These describe configuration, not current VPN
readiness or sufficient budget. Credentials, paths and endpoint overrides are
never returned. Tool input cannot expand these grants.

Reuse an active job for follow-up work. Finish or cancel it when done: the
default service limit is four active jobs shared by clients, and additional
starts return `capacity`. `storage_not_permitted` means evidence is available
during the job but cannot be kept afterward; it is not a failed search or read.
Read required ephemeral evidence before finishing the job.

Fetch example (substitute the returned job UUID):

```json
{"job_id":"00000000-0000-4000-8000-000000000001","urls":["https://example.com/"],"mode":"http"}
```

HTTP retrieval removes URL fragments before caching, redirects and archival:
fragments identify client-side views, not HTTP resources. Browser navigation
keeps fragments so hash-based pages remain addressable.

`auto` first performs HTTP extraction. A successful result with a JavaScript hint
is rendered when the operator has explicitly enabled and configured the browser.
HTTP policy, access or extraction errors never trigger rendering. Without an
enabled browser, the HTTP result retains its `javascript_required` flag.

`browser` uses a one-shot reading session. Its result includes `closed: true`;
the returned session ID cannot be used for further actions. Browser work within a
batch is bounded by browser concurrency, while HTTP work retains its own limit.
Persistent sessions share the global pool, so capacity failures remain visible.

`provider` is an explicit opt-in to a granted cloud scrape provider (the
configured `scrape_order`, currently Firecrawl and Spider). It is never selected
by `auto`, and it runs the same robots/`PublicUrl` policy check before the
provider call, so an access block is never bypassed. The result names the
provider and keeps the raw provider JSON and the derived text as separate
representations. Strict privacy disables scrape providers; an unavailable or
unconfigured provider returns `provider_unavailable`.

`crawl` is an optional object, `{"pages": <1..=32>, "depth": <0..=4>}`, and is
valid only with `mode` `http` or `auto` (with `browser` or `provider` it is
`invalid_request`). It is a bounded, same-origin crawl from each seed URL, not a
general crawler. The seed is fetched exactly as usual; the service then follows,
breadth-first, only links whose `origin` equals the seed's origin from the seed's
saved links representation. `pages` counts total pages including the seed and
`depth` counts link hops from the seed (`0` fetches only the seed). Both are
clamped down to the operator's `limits.crawl_pages` (default 16, maximum 64) and
`limits.crawl_depth` (default 2, maximum 5); a client can only reduce those, and
values outside the API range are rejected. Crawling is single-origin per call:
multiple seed URLs are crawled independently and links never cross an origin
boundary.

Every crawled page runs the normal fetch path, so redirects, retries, robots,
cache, budgets and immutable evidence match a directly requested fetch, and each
crawled page owns source and representation IDs usable with `research_read`. The
seed item keeps its normal shape and adds a `crawl` summary:
`requested_pages`, `requested_depth`, `effective_pages`, `effective_depth`,
`fetched`, `skipped`, `failed`, `paused`, `partial` and a bounded `pages` list.
The seed itself remains the normal item; `fetched`, `skipped` and `failed` count
discovered pages only, and each entry in `pages` carries its own `url`, `depth`,
state, source and `raw_source_id`.
A valid robots disallow or access block skips only that discovered page. An
unavailable or throttled robots document (network/5xx or 429) pauses discovery
for that origin, keeping the seed and already-fetched pages; a robots block is
never bypassed. An over-budget or cancelled crawl returns the pages it already
has with `partial: true`, and a paused origin is not resumed automatically.

Successful auto-rendering returns the browser result with the original HTTP
result under `http`. If rendering fails before a snapshot is available, the HTTP
result remains at the top level with `render_error` and partial coverage. A
snapshot with pending requests, request errors, truncated references or extraction
failure also reports partial coverage; its DOM evidence remains readable.

`research_browser` sessions belong to their job and owner. `open` returns a live
session; subsequent actions require its `session_id`. `follow_link` and `expand`
require a reference from an observed page version. `scroll` takes `direction` of
`up` or `down`. `close` waits for worker and archive cleanup and does not charge an
additional browser action. Disabled browser operations return `provider_unavailable`.
Cross-origin JSON read POSTs may make a real CORS `OPTIONS` request first. The
preflight is limited to an operator-granted POST origin/path, carries no cookie
or referrer, requests only `POST` and optionally `content-type`, and cannot
authorize the later body. The browser still requires a valid upstream CORS
response; the actual POST must pass its exact reviewed body rule. No general
form, mutation or custom-header capability is exposed.

## Evidence and continuation

### Stored representations

Source IDs identify immutable retrieval records; representation IDs identify the
raw entity, parsed text, a PDF page, optional Readability output or extracted
links. Every representation includes SHA-256, byte size, extraction version and
its parent representation where applicable. A completed parsed source contains
its own raw representation; `raw_source_id` identifies the earlier record saved
before parsing, subject to the same eviction policy.

`primary_representation.text` is a boolean indicating a text representation,
not the text itself. Pass the source and representation IDs to `research_read`
with `kind: "source"`; the returned `content` field contains the actual text.

Browser `dom_source_id` identifies the DOM record saved before extraction;
`source` identifies its extracted result (or that DOM record on extraction
failure). Original HTTP entities are separately identified in
`session_http_entities`. These receipts are cumulative for the session, not an
exact dependency graph for a particular snapshot. One-shot fetches include
receipts collected through shutdown; the snapshot's pending/error flags still
describe what was observed when it was captured.

`research_read` with `kind: "source"` takes `source_id`, `representation_id` and
either `cursor` or `start`, plus optional `max_bytes`. `pdf_page` substitutes a
one-based `page`. Never supply both a cursor and an explicit offset. Text offsets
count Unicode scalar values, including combining marks separately; line numbers
are one-based. Binary chunks are base64 with byte offsets. Cursors bind source,
representation and hash, and never bypass the UID ownership check.

The default tool-result bound is 64 KiB. Large results return `truncated: true`,
coverage, usage and a `report_id`. Read with `kind: "report"` and its `next_start`
to reconstruct the complete JSON result. Reports last at most five minutes,
share a 16 MiB memory cap, may be evicted sooner, and active-job reports disappear
when that job closes. `source_expired` makes expiration or eviction explicit.
Chunk content leaves 2 KiB for its metadata; the configured result bound must be
at least 4 KiB. Complete link lists remain available as saved representations
even when the immediate preview is truncated.

All retrieved text, snippets, titles, URLs and quotes are untrusted data. Tool
arguments cannot contain headers, credentials, provider endpoints, filesystem
paths, scripts, arbitrary clicks or new grants.

## Optional summarization (`kind: "summary"`)

`research_read` with `kind: "summary"` is the separately enabled LLM expansion.
It takes `job_id`, `source_id` and an optional `representation_id` (default: the
source's primary text representation; only `text: true` representations are
accepted, otherwise `invalid_request`/`not_found`). No prompt, model, provider or
instruction can be supplied. Because it is paid work, it is admitted exactly
like search/fetch/browser: it needs an open job of the same owner, ready
egress, and it honours call cancellation, job cancellation and the job deadline;
its cost is reserved against the job/day budgets. Without a granted provider in
`summarize_order`, or under strict privacy, it returns `provider_unavailable`
before any network call, and every other operation is unaffected: Research does
not depend on it.

The service reads the saved text, cuts it at the operator's
`limits.summary_input_bytes` on a character boundary, and sends it to the first
granted provider (fallback only for unavailable/authentication/rate-limit/invalid
outcomes, as for search). The result has `state` (`success`, `partial` when the
input was cut or the completion stopped at the token limit, or `empty` when the
text is blank — no request is made then), an `input` block (`source_id`,
`representation_id`, `sha256`, `characters`, `truncated`), the bounded `summary`
string with `summary_truncated`, `generated: true`, `provider`, `model`,
`finish_reason`, token counts when reported, and `usage`. The summary is stored
as a **new source** (`source`, `summary_representation`) whose `provider` is the
adapter name, with the exact provider JSON and the generated text as separate
representations; the summarized evidence is never modified. A summary is
generated, untrusted data — never a quotation of the source. Read the original
representation for exact quotes.

## Lifecycle and errors

Clients sharing a Unix UID share the same authority. Another UID cannot retrieve
their evidence. A dropped client cancels the jobs it created. A dropped MCP call
sends request cancellation, while leaving its job available. Finish/cancel waits
for worker and storage operations to release their leases before cleanup.

A lost Unix session fails its dispatched calls with `cancelled`; those operations
are never retried automatically, since their effects may already have occurred.
Undispatched calls can open a fresh session with the same bounded startup retry
policy, repeating the handshake and peer-UID checks. Cancelling a reconnect does
not poison later calls. Explicit client close prevents further connections.

A root-authored egress lease pauses admission while draining. Offline or changed
exit generation interrupts jobs and retains practical evidence. Reading saved
sources and inspecting jobs does not require working egress. Typical failures
include `destination_denied`, `policy_denied`, `access_blocked`, `budget_exceeded`,
`rate_limited`, `egress_unavailable`, `egress_changed`, `source_expired` and
`cancelled`. Upstream bodies and credentials never become diagnostic strings.

RPC uses a four-byte big-endian length followed by versioned JSON, at most 1 MiB.
The initial `hello` confirms version 1 and the exact tool set. IDs increase on
each connection; responses may finish out of order. There are at most 16 active
calls per connection and 32 connections. A partial frame body times out after
30 seconds. Authentication is by Unix peer credentials, not agent-supplied IDs.
