# Provider adapters: Spider and Firecrawl (scrape)

Adapter design notes for Spider and Firecrawl. The Rust service implements
these adapters and tests them with synthetic responses. Current data grants and
limitations are documented in [providers.md](providers.md).

**No live provider call is part of this work.** Every claim below is from the
primary documentation fetched on 2026-09-16 (sources in §9). Fields that could
not be confirmed are marked **UNVERIFIED** rather than guessed.

---

## 0. Summary of the recommendation

| Item | Spider | Firecrawl |
| --- | --- | --- |
| Endpoint | `POST https://api.spider.cloud/scrape` | `POST https://api.firecrawl.dev/v2/scrape` |
| Auth | `Authorization: Bearer <cred>` | `Authorization: Bearer <cred>` |
| Content-Type | `application/json` | `application/json` |
| Response | JSON array, one object per page | JSON object `{success,data}` |
| Raw origin content | `content` (with `return_format: ["raw","markdown"]`) **UNVERIFIED shape** | `data.rawHtml` |
| Derived text | `content` markdown item | `data.markdown` |
| Cost | variable, USD in `costs.total_cost` | deterministic credits per page |
| Force | `request=http`, `proxy_enabled=false`, `cache=false`, `fingerprint=false`, `session=false`, no `/unblocker` | `proxy=basic`, `storeInCache=false`, `skipTlsVerification=false`, `onlyCleanContent=false`, no `actions`/`profile` |

Both adapters reuse the `Transport` POST verb that the Tavily work adds; they
must never build a raw `reqwest` client (that would bypass the egress proxy,
public-DNS pinning, per-origin admission and the ledger).

---

## 1. Trust model

- Providers are operator-granted, never tool-granted. A provider is usable only
  when `ProviderConfig.enable` is true, `Capability::Scrape` is granted,
  `DataClass::Urls` **and** `DataClass::Content` are granted, a credential name
  is configured and `request_micro_usd` is present. A key alone grants nothing
  (`config.rs::provider_allowed`, existing D1 rule).
- `DataClass::Urls` covers sending the target URL to the provider;
  `DataClass::Content` covers the provider returning page content that we may
  store or surface. `Config::validate` must require both for any enabled
  `Scrape` provider. `config.rs::provider_allowed` currently maps
  `Scrape => DataClass::Urls`; extend it to require the set `{Urls, Content}`.
- Privacy modes: `Config::provider_allowed` already denies any non-`Search`
  capability in `Privacy::Strict`. That is correct and must stay: strict mode
  disables cloud scraping entirely. Practical mode persists provider evidence
  only when the account's `storage_rights` is true; otherwise the source is
  marked `SourceWarning::StorageNotPermitted` and is job-ephemeral (mirrors
  `Service::search` for Brave).
- Credentials come only from `CREDENTIALS_DIRECTORY` via the existing
  `from_credentials(ProviderConfig, &Path)` pattern. No environment-variable key
  discovery, no tool-selected path, no file path in config or Nix store.
  Credential bytes are read bounded (≤ 4096), must be single-line printable, and
  the header is marked `set_sensitive(true)`.
- Provider responses are untrusted data. `Source.untrusted = true`, content is
  never an instruction, and provider-supplied URLs (final URL, links) are
  re-parsed through `PublicUrl::parse` before use.
- **No live calls in tests.** Unit/integration coverage uses synthetic
  `Transport` fixtures returning canned JSON, exactly like the Brave tests in
  `src/provider.rs`.

---

## 2. Endpoints, methods, auth and exact request JSON

Endpoints are compile-time constants in `src/provider.rs` next to
`BRAVE_ENDPOINT`, parsed with `PublicUrl::parse` so origin/path pinning applies:

```rust
pub const FIRECRAWL_ENDPOINT: &str = "https://api.firecrawl.dev/v2/scrape";
pub const SPIDER_ENDPOINT:    &str = "https://api.spider.cloud/scrape";
```

Both are `POST`, `Content-Type: application/json`, exactly one service-authored
header beyond the body:

```
Authorization: Bearer <CREDENTIALS_DIRECTORY/<name>>
Accept: application/json
```

There is no redirect following (the transport already disables it), no
pagination following, and no provider-supplied header is ever copied.

### 2.1 Firecrawl request

```json
{
  "url": "<target>",
  "formats": ["markdown", "rawHtml"],
  "onlyMainContent": true,
  "onlyCleanContent": false,
  "skipTlsVerification": false,
  "storeInCache": false,
  "proxy": "basic",
  "maxAge": 0,
  "mobile": false,
  "waitFor": 0,
  "timeout": 30000,
  "removeBase64Images": true,
  "blockAds": true,
  "parsers": []
}
```

- `timeout` is bounded to `min(limits.http_seconds * 1000, 300000)` and ≥ 1000
  (Firecrawl's documented range). It must not exceed the job deadline.
- `parsers: []` asks Firecrawl not to run its own per-page PDF pipeline, which
  both removes the `+1 credit / PDF page` cost and keeps document parsing inside
  our isolated Poppler worker (R08). The consequence per the API reference is a
  base64 body at a flat 1 credit; the exact response field for this case is
  **UNVERIFIED** and must be pinned by a synthetic fixture before shipping
  (§8). If the fixture shows a different contract, the fallback is to request
  `"formats": ["markdown","rawHtml"]` with the PDF parser bounded by
  `maxPages = limits.pdf_pages`, and to budget `+1 credit × pages`.
- `headers` is deliberately absent. If the operator wants a request language, it
  is set through `location.languages` (see §3.4), never through arbitrary
  `headers`.
- No `actions`, no `profile`, no `zeroDataRetention`, no `lockdown`, no
  `formats` object other than the two strings, no `location` by default.

Auth and endpoint confirmed at the Firecrawl scrape API reference and
`v2-openapi.json`: server `https://api.firecrawl.dev/v2`, `bearerAuth` security,
`POST /scrape`.

### 2.2 Spider request

```json
{
  "url": "<target>",
  "request": "http",
  "return_format": ["raw", "markdown"],
  "respect_robots": true,
  "cache": false,
  "proxy_enabled": false,
  "fingerprint": false,
  "session": false,
  "readability": true,
  "filter_output_main_only": true,
  "return_page_links": false
}
```

- `request: "http"` is mandatory: Spider's default is `"smart"`, which silently
  escalates to a headless browser. D1 requires stealth/anti-bot escalation to be
  disabled, and unrecognized `request` spellings silently fall back to `"http"`,
  so the value must be the exact documented string.
- `return_format` is an array to obtain both raw HTML and markdown. The response
  shape for an array `return_format` is **UNVERIFIED** (the reference only
  documents the scalar field `content`). Fallback if the fixture cannot confirm
  the array shape: request `"markdown"` only and store the untrusted provider
  JSON envelope as the raw `HttpEntity` (see §4).
- `respect_robots: true` is the documented default; keep it explicit.
- `cache: false` avoids Spider's 2-day HTTP cache and any provider-side reuse.
- `proxy_enabled`, `fingerprint`, `session` are all forced off/away from their
  defaults (`proxy_enabled` default false, `fingerprint` default true,
  `session` default true).
- No `anti_bot`, no `stealth`, no `automation`, no `execution_scripts`, no
  `screenshot`, no `webhooks`, no `run_in_background`, no `country_code`/
  `locale` by default, no `/unblocker`.

Auth and endpoint confirmed at `spider.cloud/llms.txt` and
`spider.cloud/llms-full.txt`: base `https://api.spider.cloud`, all content
routes are POST, `Authorization: Bearer`, response is a JSON array.

> Doc-availability note: `https://spider.cloud/docs/` returns 404 and the
> rendered API-reference page is JavaScript-heavy. The authoritative material
> used here is `spider.cloud/llms.txt`, `spider.cloud/llms-full.txt` and
> `spider.cloud/openapi.yaml`. The OpenAPI `ScrapeSuccessResponse` schema says
> `{result: string}`, which contradicts the array documented by `llms-full.txt`;
> this is treated as a schema error and the array shape is the working
> assumption, still to be confirmed by fixture.

---

## 3. Forced privacy and security flags

The rule from D1 and the implementation plan: keep generated answers, automatic
parameter selection, automatic routing and stealth escalation disabled. The
defaults of both providers violate several of these, so every adapter must set
the safe value explicitly and a test must assert it is present.

### 3.1 Firecrawl — forced values

| Field | Default | Forced | Why |
| --- | --- | --- | --- |
| `skipTlsVerification` | `true` | `false` | Default would disable TLS verification on the provider's fetch; we never accept a downgraded channel. |
| `storeInCache` | `true` | `false` | Default stores the page in Firecrawl's index/cache. Force off for no-storage and strict; also the documented "data protection concerns" switch. |
| `proxy` | `auto` | `basic` | `auto` retries with enhanced proxies automatically; `enhanced` is anti-bot escalation. D1 forbids stealth escalation. `basic` is documented as the plain pool. |
| `onlyCleanContent` | `false` | `false` | Beta LLM post-pass; D1 forbids generated/LLM processing. Default is already false but is pinned so a future default change cannot enable it. |
| `onlyMainContent` | `true` | `true` | Deterministic HTML-level filter, no LLM (documented). Keeps output clean without an LLM. |
| `maxAge` | `172800000` (2 days) | `0` | Never serve a provider-cached copy; freshness must be ours, and a cached copy defeats no-storage intent. |
| `formats` | SDK-dependent | `["markdown","rawHtml"]` | No `summary`/`json`/`question`/`highlights` (all LLM, `+4 credits`) and no `screenshot`/`audio`/`video`. |
| `actions` | absent | absent | No click/type/scroll/`executeJavascript`/PDF generation. |
| `profile` | absent | absent | No persistent cookies/localStorage/session sharing. |
| `mobile` | `false` | `false` | No device fingerprint variation. |
| `waitFor` | `0` | `0` | No JS wait behavior. |
| `parsers` | `[{"type":"pdf",...}]` (+1 credit/page) | `[]` | Avoid Firecrawl's PDF/OCR pipeline and per-page cost; parse locally (§2.1). |
| `headers` | absent | absent | No caller-controlled headers/cookies; language goes through `location.languages` only. |
| `zeroDataRetention` | `false` | `false` (unless operator enterprise contract) | Enterprise-gated; only enabled if the operator's contract actually has it. **UNVERIFIED** availability. |
| `lockdown` | `false` | `false` | Cache-only mode changes semantics; not used. |

`zeroDataRetention` is also incompatible with `onlyCleanContent` per the API
reference, and costs `+1 credit / page` if enabled.

### 3.2 Spider — forced values

| Field | Documented default | Forced | Why |
| --- | --- | --- | --- |
| `request` | `smart` | `http` | `smart` auto-escalates to a real browser; D1 forbids stealth escalation. |
| `proxy_enabled` | `false` | `false` | Premium/residential proxy pools; also cost ×1.5. |
| `proxy` | unset | unset | No residential/mobile/ISP pool. |
| `fingerprint` | `true` | `false` | Advanced browser fingerprinting. |
| `session` | `true` | `false` | Would persist headers/cookies across the call. |
| `cache` | `true` (2-day window) | `false` | No provider cache reuse; freshness is ours. |
| `respect_robots` | `true` | `true` | Keep true, matching local behavior. |
| `anti_bot` / `stealth` | **UNVERIFIED** | `false` if sent | Listed in the OpenAPI `RequestParams` but their defaults are not documented in the fetched pages; force `false` explicitly if the adapter sends them at all, and assert it. |
| `automation` / `execution_scripts` | absent | absent | No browser actions or scripts. |
| `screenshot` | absent | absent | No screenshots; the `/screenshot` route is not used. |
| `webhooks`/`run_in_background` | absent | absent | No push delivery or untracked background jobs. |
| `country_code`/`locale` | unset | unset by default | See §3.4. |
| `/unblocker` | n/a | not used | `+10–40 credits` per success and heavier fingerprinting/proxy rotation. |
| `/ai/*` | n/a | not used | Prompt-based extraction; needs an AI plan. |

Cost-relevant Spider modifiers that must never be enabled: `proxy` pools
(×1.2–×2), `proxy_enabled` (×1.5), `/unblocker` (+10–40 credits), `/ai/*`.
`/unlimited/*` is a different billing model and is out of scope.

### 3.3 Bounded cost, pages and time

- Pages: `/scrape` returns exactly one page. Do not use `/crawl`; if bounded
  crawling is added later it is a separate design. `limit` is therefore not
  sent, and Firecrawl's crawl pre-flight credit check is not involved.
- Time: `request_timeout`/`timeout` on Spider and `timeout` on Firecrawl are
  capped by `limits.http_seconds` and the job deadline. The transport's own
  `timeout_at(deadline, …)` remains the hard backstop.
- Bytes: the response body is capped by `limits.pdf_bytes` (provider JSON) and
  the extracted HTML by `limits.html_bytes`; the transport's one-look-ahead
  overflow detection is reused.
- Both providers are called through the normal `Transport`, so global/per-origin
  admission, the egress proxy and the ledger apply unchanged.

### 3.4 Location / country / languages and the D2 interaction

- Firecrawl `location.country` is ISO 3166-1 alpha-2; `location.languages` is an
  Accept-Language ordered list. Spider exposes `country_code` and `locale`.
  These map cleanly onto our existing `country` / `language` inputs.
- **Default: send neither.** Firecrawl's own guidance is to leave `location`
  unspecified, and Firecrawl routes through US proxies by default. Sending a
  region steers third-party proxy selection, which we cannot audit.
- If an operator explicitly opts in, the value must come from the trusted
  observation lease's exit region (D2), never from tool input, and only when the
  observation region is known and maps cleanly to an ISO code. If the region is
  unknown, the field is omitted rather than guessed.
- D2 caveat: D2 rotates **our** browser profile to match the observed VPN exit.
  A scrape provider uses its **own** egress network. Setting a provider location
  to the same region keeps the declared locale/region coherent, but it does not
  make the provider's exit the VPN exit and must never be presented as such. The
  provider's egress is a separate, unaudited hop; this is a risk to record
  (§7), not something the adapter can fix.

---

## 4. Response mapping into the evidence model

Both adapters return a `ScrapeRecord` shaped like `fetch.rs::FetchRecord`
(`source`, `raw_source_id`, `title`, `links`, `error`, `cache_hit`) plus the
derived text id, and insert through `EvidenceStore::insert` /
`Archive::insert` unchanged. `Source.provider` is `Some("spider")` or
`Some("firecrawl")`; `Source.untrusted` is always true.

Evidence bundle order (indices matter: `Evidence.derived_from` refers to an
earlier entry in the same bundle, enforced in `archive.rs`):

| # | Kind | Source field | `extraction_version` | `text` |
| --- | --- | --- | --- | --- |
| 0 | `HttpEntity` | whole provider response body (raw JSON) | `spider-http-json/v1` / `firecrawl-http-json/v1` | `true` |
| 1 | `HttpEntity` | origin HTML: Spider `content` raw item / Firecrawl `data.rawHtml` | `spider/raw/v1` / `firecrawl/v2/rawHtml/v1` | `false` |
| 2 | `Text` | derived markdown: Spider `content` markdown item / Firecrawl `data.markdown` | `spider/markdown/v1` / `firecrawl/v2/markdown/v1` | `true` |
| 3 | `Links` | optional `links` (Spider `return_page_links`) | `research-links/v1` | `true` |

- The raw JSON in #0 is the immutable provider evidence (it also carries
  `costs` and `metadata`); #1 is the origin content the provider observed; #2 is
  the provider's derived text, referencing #1.
- If the Spider array `return_format` shape cannot be confirmed (§2.2), #1 is
  omitted and #2 is the only content representation; the provider JSON #0 is
  still the raw evidence.
- Firecrawl: use `data.metadata.statusCode` as the page status and
  `data.metadata.error` for detail; a non-2xx page status maps to the existing
  `ErrorCode` (`AccessBlocked`, `NotFound`, `RateLimited`, else
  `InvalidResponse`), mirroring `fetch.rs::process`. A page error does **not**
  discard the retained raw evidence, and the item is `Partial`.
- Spider: each array element has its own `status` and `error`; map like local
  fetch. `duration_elasped_ms` is the real (misspelled) wire key and is ignored.
- Final URL: prefer the request target; if the response reports a different URL,
  parse it with `PublicUrl::parse` and only then use it as `final_url`.
  Provider-reported URLs that fail the policy are dropped (links) or replaced by
  the target (final URL), with `omitted`/partial coverage, exactly like
  `provider.rs::parse_search`.
- Unicode/raw fidelity: JSON strings are stored verbatim as UTF-8; text
  representations must be valid UTF-8 (`archive.rs` rejects otherwise).
  `bounded_text` is applied only to titles/snippets for the API brief, not to
  the archived bytes. Chunking already counts Unicode scalar values.
- Bounds/truncation: an oversized provider body yields `ErrorCode::SizeLimit`
  with the already-retained bytes; a truncated derivation adds
  `SourceWarning::Truncated`; partial pages add `SourceWarning::PartialExtraction`.
- Extraction version strings are ≤ 80 bytes (archive constraint) and identify
  provider, version and representation; bump `v1` on any meaning change.

---

## 5. Cost model

Money stays integer micro-USD in `budget.rs`; `Charge` and `Reservation` are the
only accounting primitives.

- Operator declaration. For each enabled scrape provider, `request_micro_usd`
  is mandatory and bounded to ≤ 1_000_000_000 (existing check). Absence disables
  the provider; there is no free/default price.
  - Firecrawl is deterministic once options are forced: 1 credit/page. The
    operator sets `request_micro_usd` to their plan's credit price, e.g. PAYG
    Hobby is 1,000 credits per US$5 → `5000`. Promotional credits are not
    subtracted (same rule as Brave).
  - Spider is variable (`$1 / 10,000 credits` plus `$1/GB` plus
    `$0.0001/CPU-minute`). `request_micro_usd` is a **per-page ceiling** chosen
    by the operator from the pricing page; the adapter reserves the ceiling.
- Atomic reservation before the call. The adapter reserves
  `Charge { micro_usd: ceiling, requests: 1, documents: 1, bytes: max }` via
  `Ledger::reserve` before the provider call, so concurrent jobs cannot pass the
  `$0.50/job` or `$5/day` caps (R17). One page per request keeps
  `documents`/`requests` accounting honest.
- Settlement.
  - Firecrawl HTTP status ≥ 400 is unbilled per the billing reference
    ("Firecrawl returned no document: 0 credits"); use
    `errors_are_unbilled = true`. A 200 that returned a document settles at the
    configured fixed price even when the page's own status is 403/404 (docs).
  - Spider bills consumed bytes/compute including error statuses
    ("Do not assume a failed page is free"), so `errors_are_unbilled = false`:
    a non-2xx response keeps the hold. On a 200, parse `costs.total_cost` (USD),
    convert to micro-USD rounding up, clamp to the ceiling, and settle the
    actual. `costs == null` means nothing was billed and settles 0; a **missing**
    `costs` key keeps the hold (unknown). Any malformed/NaN/negative/overflowing
    value keeps the hold rather than guessing a number.
  - `errors_are_unbilled` and the settle amount must be computed before the body
    is fully consumed where the transport allows it; the existing
    `Reservation::remember_cost` / `finish` path already supports an unknown
    outcome that keeps its hold.
- Unknown-cost policy. If the ceiling/price is absent → provider disabled. If a
  response cannot establish the amount → keep the hold and mark the item
  partial; never release to zero on uncertainty. This is the existing R17 rule.
- Transport interface note. `src/http.rs::HttpRequest` today carries a single
  `micro_usd` and `Transport::get` settles `Some(micro_usd)` on 2xx. For Spider's
  variable cost the POST verb the Tavily work adds must return enough for the
  adapter to settle the parsed actual (e.g. it returns the `Reservation`, or
  accepts a cost ceiling plus a post-parse settle). Whichever shape lands, the
  scrape adapters must not add a second reservation on top of the transport's
  own. Coordinate this explicitly with the Tavily change before implementing;
  the conservative fallback is to settle at the ceiling (never under-count).

---

## 6. Wiring plan (existing symbols)

### 6.1 Configuration (`src/config.rs`, `nix/module.nix`)

- Generalize `Config::validate`: today it hardcodes `name != "brave"`, requires
  every provider capability to be `Search`, and rejects any non-`brave` entry in
  `search_order`. Change to: known names `brave`/`tavily` (search) and
  `spider`/`firecrawl` (scrape); each enabled provider must have a non-empty
  credential name in the existing `credential_name` format and a
  `request_micro_usd`.
- Add `Config.scrape_order: Vec<String>` (default empty) validated exactly like
  `search_order`: no duplicates, ≤ 8, and no member may lack `Capability::Scrape`.
  **Scrape providers must not appear in `search_order`** and search providers
  must not appear in `scrape_order`; validation rejects both.
- `Config::provider_allowed(name, Capability::Scrape)` requires `enable`,
  `Capability::Scrape`, and `data ⊇ {DataClass::Urls, DataClass::Content}`, and
  stays `false` in `Privacy::Strict`.
- Nix module: add per-provider `apiKeyFile`/credential names for `spider` and
  `firecrawl` and a `scrapeOrder` option, keeping secrets out of the store
  (module file is owned by another agent; specify the option shape only).

### 6.2 Adapters (`src/provider.rs`)

- `pub struct Firecrawl { credential: HeaderValue, price: u64, storage_rights: bool }`
  and `pub struct Spider { … }`, each with `new(config, bytes)` and
  `from_credentials(config, directory)` mirroring `Brave`, and a
  `scrape(&self, http: &dyn Transport, context: &Context, target: &PublicUrl, maximum: u64) -> Result<ScrapeResponse>`.
- `ScrapeResponse { source_inputs, raw, text, links, provider, retrieved_at, storage_rights }`
  (exact shape should mirror `SearchResponse`).
- Parse functions (`parse_firecrawl`, `parse_spider`) are pure and unit-tested
  with the synthetic fixtures; they enforce the field presence, status mapping,
  bounds and Unicode rules of §4/§5.
- `Context`, `bounded_text` and the `Brave` structure are reused; do not fork
  transport, retry or rate-limit logic.

### 6.3 Transport (`src/http.rs`)

- Reuse `Transport::post` (added by the Tavily work) with
  `HttpRequest { micro_usd: ceiling, errors_are_unbilled, query: false }` and the
  service-authored `Authorization`/`Content-Type`/`Accept` headers. No raw
  client. Ensure the POST body size is bounded (the transport already caps
  outgoing bytes against the job budget).
- The egress proxy, DNS pinning, redirect refusal and per-origin/global
  admission apply unchanged, so provider traffic keeps the R05/R06 guarantees.

### 6.4 `research_fetch` selection (`src/api.rs`, `src/service.rs`)

- Add `FetchMode::Provider` (serialized `"provider"`) next to `Auto`/`Http`/
  `Browser`. Explicit mode is the only way to route to a scrape provider:
  - `Browser` → existing browser path.
  - `Http` → local `Fetcher::fetch` only.
  - `Auto` (default) → local `Fetcher::fetch`, then the existing browser hint;
    `Auto` **never** escalates to a provider, and never escalates on
    `AccessBlocked`/`PolicyDenied`/`RateLimited` (no bypass, no automatic
    routing, D1).
  - `Provider` → first entry of `config.scrape_order` that
    `provider_allowed(name, Capability::Scrape)`; `ProviderUnavailable` if none.
- In `Service::fetch_item`, add a `scrape_item` branch that:
  1. parses the target with `PublicUrl::parse`;
  2. runs the same robots check as the local path (see §6.5) before any provider
     call;
  3. calls the selected adapter with the same `Context`, then inserts the
     evidence bundle and returns an `Item` with `provider`, `source`,
     `raw_source_id`, text id and warnings, matching the local shape.
- Cache: add a `scrapes: Cache<ScrapeRecord>` on `Service`, or extend the
  `Fetcher` document cache key to include the provider name. Either way the key
  must include the provider and the forced-flag set; `Service.policy` already
  hashes the whole `Config` (including `providers`), so privacy mode and grants
  are part of the key. Honor `storage_rights`/strict exactly like
  `Service::search`.
- `src/bin/research-service.rs`: construct `Option<Firecrawl>`/`Option<Spider>`
  only when `config.provider_allowed(name, Capability::Scrape)`, reading
  `CREDENTIALS_DIRECTORY`; add them to `Dependencies`.

### 6.5 Robots, policy and access blocks

- Provider scraping must not bypass access blocks. Before sending a URL to a
  provider, call the existing robots decision
  (`robots.rs::RobotsDocument::decide(target, AccessKind::SelectedPage,
  robots.selected_page_error_allows)`); a disallowed path returns
  `PolicyDenied` without any provider call. Network/5xx robots failure keeps the
  existing selected-page warning behavior.
- `Auto` must not convert a local `AccessBlocked`/`PolicyDenied` outcome into a
  provider fetch. Only an explicit `Provider` request (which still passes the
  robots check) reaches a provider.
- Record the provider-observed page status in the item so an operator can see
  that a block was reported, not bypassed.

### 6.6 Archive and reports (`src/archive.rs`, `src/api.rs`, `src/reports.rs`)

- No schema change is needed: `Source.provider`, `RepresentationKind::{HttpEntity, Text, Links}`,
  `SourceWarning` and the chunking/Unicode rules all already cover provider
  evidence. `SourceBrief::from` already surfaces `provider` and chooses a text
  `primary_representation`.
- Add `SourceWarning` only if a new condition appears; prefer reusing
  `Truncated`, `PartialExtraction`, `StorageNotPermitted`.

---

## 7. Open questions and risks

1. **Transport POST/settlement contract.** The exact `Transport::post` shape is
   being decided by the Tavily work. Spider's variable cost needs a settle-after-
   parse path; until it exists, use ceiling settlement and record the
   over-reservation. Must not double-reserve.
2. **Spider array `return_format` response shape** is unverified. Pin it with a
   fixture or fall back to markdown-only plus the JSON envelope as raw evidence.
3. **Spider `anti_bot`/`stealth` defaults** are not documented in the fetched
   pages. Force `false` if sent; otherwise their contribution to "stealth
   escalation" is unknown and should be recorded.
4. **OpenAPI vs prose conflict** for the Spider `/scrape` response. Treat the
   prose array as authoritative; verify by fixture.
5. **Firecrawl `parsers: []` response field** and the base64/flat-credit
   behavior are unverified. Fallback is the bounded PDF parser with
   `maxPages`.
6. **Third-party egress.** Both providers fetch from their own networks; the
   VPN/exit-region guarantees (D2, R05–R07) do not extend to them. Provider
   location fields only align declared locale, not the actual exit, and must not
   be described as VPN-consistent.
7. **Provider-side retention.** `storeInCache=false`/`cache=false` reduce but do
   not prove zero retention; Firecrawl ZDR is enterprise-gated and unverified.
   The operator's contract, not the flag, decides actual retention.
8. **Billing drift.** Credit prices and plan structure change; revalidate before
   implementation and keep the price operator-supplied, never hardcoded.
9. **Robots bypass by construction.** A provider may successfully fetch a page
   our local path is blocked from. The explicit-mode + robots-check rule limits
   this, but an operator who enables `Provider` deliberately accepts that the
   provider's fetch path differs from ours. Document this in the operator docs.

---

## 8. Minimal test plan (synthetic only)

All tests use a `Transport` fixture like the Brave tests; no live call.

Configuration / trust:
1. `spider`/`firecrawl` enabled with `Capability::Scrape` but missing
   `DataClass::Content` → `Config::validate` error.
2. A scrape provider listed in `search_order` → validation error; a search
   provider in `scrape_order` → validation error.
3. `Privacy::Strict` → `provider_allowed(name, Capability::Scrape)` is false.
4. No credential / no `request_micro_usd` → provider not constructed.

Request construction (assert on the captured request):
5. Correct method, origin, path, `Authorization: Bearer`, `Accept`,
   `Content-Type`; credential header is `is_sensitive()`.
6. Every forced flag from §3 is present with the safe value; every forbidden
   field (`actions`, `profile`, `waitFor`/`automation`, `execution_scripts`,
   `screenshot`, `headers`, `location` by default, `webhooks`,
   `run_in_background`, `anti_bot`, `stealth`, `proxy_enabled`) is absent or
   false.

Parsing / evidence:
7. A well-formed response produces representations #0–#2 with the right kinds,
   `extraction_version`s and `derived_from` links; `provider` is set; Unicode
   quotes/emoji survive byte-for-byte.
8. An oversized body → `SizeLimit` with retained raw bytes.
9. Malformed JSON / missing `data` / non-object Spider page → `InvalidResponse`
   with visible partial coverage.
10. A private/loopback URL in `final_url` or links → dropped/denied, not stored.
11. Firecrawl page `statusCode` 403/404 maps to `AccessBlocked`/`NotFound` while
    raw evidence and the cost hold are retained.
12. Spider per-page `status`/`error` maps correctly and keeps `Partial`.

Cost:
13. Reservation is held before the call (fixture asserts the ledger usage while
    the future is pending, as `fetch.rs` does for PDF reservations).
14. Firecrawl 402/429/500 is unbilled; a 200-with-document settles the fixed
    price.
15. Spider parses `costs.total_cost` and settles the converted amount; `null`
    settles 0; missing/NaN/negative/over-ceiling keeps the hold.
16. Concurrent provider fetches cannot exceed `job_micro_usd`/`daily_micro_usd`.

Policy:
17. Robots-disallowed path → no provider call, `PolicyDenied`.
18. Local `AccessBlocked` does not trigger a provider fetch in `Auto`.
19. Strict mode and missing-storage-rights behavior matches Brave
    (`StorageNotPermitted`, job-ephemeral source).

Integration: add the two adapters to the synthetic service/`Dependencies`
fixture so `research_fetch` with `mode: provider` returns an `Item` whose
`provider`, `source` and `raw_source_id` are consistent across a
`research_read` round-trip.

---

## 9. Sources (fetched 2026-09-16)

| URL | Confirms |
| --- | --- |
| https://docs.firecrawl.dev/api-reference/endpoint/scrape | `POST /v2/scrape`, `bearerAuth`, `ScrapeOptions` defaults (`skipTlsVerification=true`, `storeInCache=true`, `proxy=auto`, `onlyCleanContent=false`, `onlyMainContent=true`, `maxAge`, `location`, `actions`, `profile`, `parsers`, `zeroDataRetention`), `ScrapeResponse` shape |
| https://docs.firecrawl.dev/api-reference/v2-openapi.json | server `https://api.firecrawl.dev/v2`, `/scrape` security/request/response schemas |
| https://docs.firecrawl.dev/features/scrape.md | formats, response metadata/status-code layers, base-1-credit and option costs |
| https://docs.firecrawl.dev/features/proxies.md | `proxy` semantics and country/proxy availability |
| https://docs.firecrawl.dev/billing.md | 1 credit/page, per-option credit costs, doc-vs-no-doc billing, ZDR |
| https://docs.firecrawl.dev/llms.txt | doc index used to discover the pages above |
| https://spider.cloud/llms.txt | base `https://api.spider.cloud`, auth, endpoint list, core parameters, array response, error codes, rate limits, pricing summary |
| https://spider.cloud/llms-full.txt | full parameter table (`request` default `smart`, `respect_robots`, `proxy_enabled`, `fingerprint`, `session`, `cache`, `return_format`), response `costs`, error/rate-limit behavior |
| https://spider.cloud/openapi.yaml | `POST /scrape` request schema (`RequestParams`, `ReturnFormat`, `RequestType`, `stealth`, `anti_bot`, redirect policy, etc.) |
| https://spider.cloud/docs/overview/ | working docs entry point (`/docs/` itself 404s) |

**UNVERIFIED fields** (do not invent values): Spider array-`return_format`
response shape; Spider `anti_bot`/`stealth` defaults; Firecrawl `parsers: []`
response field and flat-credit behavior; Firecrawl ZDR availability/price;
Firecrawl keyless-free-tier applicability (we always require a credential).
