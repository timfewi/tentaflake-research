# Provider grants, data and billing

The implemented search providers are Brave Web Search, Tavily and a self-hosted
SearXNG instance. Firecrawl and Spider are implemented for explicit scrape,
sharing the same `ScrapeProvider` trait. An OpenAI-compatible adapter implements the separately
enabled summarization expansion. A key never activates a capability.
Operator configuration must explicitly enable each provider, grant `search` and
`queries` (search), `scrape`, `urls` and `content` (scrape), or `summarize` and
`content` plus a `model` (summarize), name its systemd credential, configure a
successful-request price and choose whether persistent storage rights are
available. Self-hosted SearXNG is the exception: it needs no credential and no
price, and instead names a bare public HTTPS `endpoint`. Search only uses
providers listed in `search_order`, scrape only `scrape_order` and
summarization only `summarize_order`; the orders are pairwise disjoint. No
environment-variable key discovery or personal model login is involved, and no
retrieval operation depends on an LLM.

No commercial adapter is selected by default: `search_order`, `scrape_order` and
`summarize_order` are empty. The NixOS module selects `searxng` only when its local
SearXNG service is explicitly enabled. Existing Brave deployments must now set
`searchOrder = [ "brave" ];` (or JSON `search_order: ["brave"]`) in addition to
their grants. Inspect effective routes with `research_job` operation `providers`.
HTTP retrieval remains available with every provider disabled, subject to egress
readiness and the usual policy/budgets.

Fallback uses only explicitly granted providers. Each attempt tracks its
transport requests: a fixed-price successful response or a documented unbilled
error may allow fallback for eligible provider errors; an uncertain paid error
or interrupted request stops it. This applies to search, scrape and summary.

The service reads only the named credential from `CREDENTIALS_DIRECTORY`. That
directory comes from the service manager; tools cannot select it. Configuration
and Nix store paths must contain credential names/runtime file paths, never keys.
Keys stay out of browser/parser environments, evidence and diagnostics.

Brave receives the query and explicitly requested language, country, count and
freshness through its fixed HTTPS API origin/path. The request disables generated
summaries, rich callbacks, spellcheck and decorations. Retrieved page content is
not sent to Brave by this adapter. Provider pagination and redirects are not
followed; URLs in results are individually validated and remain source data.

As checked on 2026-09-15, the public plan lists $5 per 1,000 search requests.
Configure `request_micro_usd: 5000` only when that matches the operator's plan;
do not subtract promotional credits from local reservations.
[Brave pricing](https://brave.com/search/api/)

Brave documents error responses as unbilled. The adapter can release that cost
reservation after receiving an error status, even if its body later exceeds a
limit. Successful statuses use the configured fixed rate. An uncertain transport
failure keeps its held amount and is not automatically retried. Eligible 429
responses use bounded Retry-After, with at most two retries, each admitted against
the job's request/query/time budgets.
[Brave rate limiting](https://api-dashboard.search.brave.com/documentation/guides/rate-limiting)

Successful responses preserve raw JSON separately from normalized result data.
Invalid/private items are omitted with visible partial coverage; valid results
survive. Query controls follow the documented 600-character/75-word maximum and
at most 20 results. Oversized titles/snippets are marked truncated.
[Brave web-search API](https://api-dashboard.search.brave.com/api-reference/web/search/get)

## Tavily

Tavily uses a fixed HTTPS endpoint, `POST https://api.tavily.com/search`, with
the named credential sent as a sensitive `Authorization: Bearer` header and a
JSON body. The adapter always sends `search_depth: basic` and `topic: general`,
sets `max_results` from the validated requested count, and forwards an explicitly
requested `language` and `freshness` (as `time_range`). The query never carries
`country`: Tavily expects English country names, while this service validates
ISO 3166-1 alpha-2 input, so forwarding it unchanged could change or fail the
search. The request disables Tavily's generated answers, raw content and
automatic parameter selection (`include_answer`, `include_raw_content`,
`auto_parameters` all false); any answer field in a response is ignored. Only
`title`, `url` and `content` per result are read.

Tavily does not document error responses as unbilled, so the adapter uses a
conservative hold (`errors_are_unbilled: false`): a failed request keeps its
reserved cost until accounting proves otherwise. A 429 is reported without an
automatic replay, including when `Retry-After` is zero. Live calls have not been
run and the request-cost ceiling is operator-configured; nothing here asserts a
current Tavily tariff.

## Firecrawl (scrape)

Firecrawl uses a fixed HTTPS endpoint, `POST https://api.firecrawl.dev/v2/scrape`,
with the named credential sent as a sensitive `Authorization: Bearer` header and
a JSON body carrying only the target URL and service-authored options. The
adapter forces the privacy- and cost-relevant flags: `skipTlsVerification: false`
(the default would disable TLS verification on the provider's fetch),
`storeInCache: false` (never store the page in Firecrawl's index), `proxy:
"basic"` (`auto` silently retries through enhanced/anti-bot proxies),
`onlyCleanContent: false` (no LLM post-pass), `maxAge: 0` (never serve a
provider-cached copy), `formats: ["markdown","rawHtml"]` (no
summary/json/question/highlights formats) and `parsers: []` (no provider-side
PDF/OCR pipeline; document parsing stays inside the isolated worker). It always
sends `onlyMainContent: true`, `mobile: false`, `waitFor: 0`,
`removeBase64Images: true` and `blockAds: true`. It never sends `actions`,
`profile`, `headers`, `location`, `zeroDataRetention`, `lockdown` or any
LLM/answer field, so no request input can widen the forced set. Firecrawl 401 and
402 map to authentication failure, 429 uses bounded `Retry-After` attempts (at
most two), 400/422 map to invalid request, and any other status is an invalid
response. Firecrawl documents HTTP errors as returning no document at 0 credits,
so the adapter sets `errors_are_unbilled: true`; a successful 200 keeps the
operator-configured fixed price. Live calls have not been run and the price is
operator-configured per successful page; nothing here asserts a current Firecrawl
tariff or subtracts promotional credits.

The raw provider JSON is archived as an `HttpEntity` under
`firecrawl-http-json/v1`, the origin `rawHtml` as a second `HttpEntity` under
`firecrawl-rawhtml/v1`, and the derived markdown as a distinct `Text`
representation under `firecrawl-markdown/v1`; the item `provider` is
`firecrawl`. Provider-reported final URLs are re-parsed through the public-URL
policy before use, and a private or malformed URL falls back to the requested
target. Robots is checked through the same selected-page decision as a local
fetch before any provider call, so an explicit provider request still cannot
bypass an access block.

## Spider (scrape)

Spider uses a fixed HTTPS endpoint, `POST https://api.spider.cloud/scrape`, with
the named credential sent as a sensitive `Authorization: Bearer` header and a
JSON body carrying only the target URL and service-authored options. The adapter
sets `request: "http"` because Spider's default `"smart"` silently escalates to a
headless browser, and it forces `proxy_enabled: false` (premium/residential proxy
pools, also a 1.5x cost step), `fingerprint: false` (browser fingerprinting),
`session: false` (no persisted headers/cookies), `cache: false` (no multi-day
provider cache), `respect_robots: true`, `readability: true`,
`filter_output_main_only: true`, `return_page_links: false`,
`return_format: ["raw","markdown"]`, and `anti_bot: false`/`stealth: false`. It
never sends `proxy`, `country_code`, `locale`, `webhooks`, `run_in_background`,
`screenshot`, `automation` or `execution_scripts`, and never uses the
`/unblocker` or `/ai/*` routes, so no request input can widen the forced set.
Spider bills failed pages, so the adapter uses `errors_are_unbilled: false` and
sends the operator's `request_micro_usd` as a per-page ceiling; the transport
settles that ceiling on 2xx and keeps the hold on non-2xx, never under-counting.
Spider's cost is variable (`costs.total_cost`) and settling that parsed amount
would need a transport settle-after-parse contract that does not exist yet, so the
ceiling is kept. HTTP 401 maps to authentication failure, 402/429 to rate
limiting, 400/422 to invalid request and any other status to invalid response.
A 429 is not automatically replayed because the failed page may be billed.

The documented response is a JSON array with one object per page, while the
OpenAPI schema instead shows a single object; the adapter accepts both and takes
the first array element. A non-2xx page `status`/`status_code` maps to the local
fetch errors (401/403 access blocked, 404 not found, 429 rate limited, else
invalid response), and a non-empty `content` string is required for the derived
text. The whole provider envelope is archived as the raw `HttpEntity` under
`spider-http-json/v1` and `content` as a `Text` representation under
`spider-markdown/v1`; the item `provider` is `spider`. The array
`return_format` response shape and the `anti_bot`/`stealth` defaults remain
unverified per `docs/provider-adapters.md`; live calls have not been run and the
price is an operator-configured per-page ceiling, not a published Spider tariff.

Practical mode persists provider evidence only when `storage_rights` is true.
Otherwise it uses a job-owned temporary archive and job-scoped cache, marked
`storage_not_permitted`. Strict mode makes all content ephemeral. Both preserve
the minimal cost ledger over restarts. Provider rights must match the account's
contract; this switch is an operator declaration, not a rights check by the tool.

## OpenAI (summarize, separately enabled)

Summarization is the only capability that sends retrieved *content* to a
provider, and Research is complete without it: it is reachable solely through
`research_read` with `kind: "summary"`, is never selected by search, fetch, auto
rendering or crawling, and an empty `summarize_order` (the default) leaves no
summary provider at all. The `openai` adapter uses the fixed HTTPS endpoint
`POST https://api.openai.com/v1/chat/completions` with the named credential as a
sensitive `Authorization: Bearer` header. It requires `enable`, the
`summarize` capability, the `content` data grant, a credential name, an
operator-selected `model` and `request_micro_usd`; strict privacy disables it
entirely ("external analysis"). The `urls` grant is optional and controls only
whether the source's final URL is included in the prompt; without it the
provider sees content alone.

The request carries exactly `model`, two messages (a fixed system instruction
that frames the retrieved text as untrusted data, and a user turn containing the
bounded text inside `<content>` tags), `max_completion_tokens` from
`limits.summary_output_tokens` (default 1024), `n: 1`, `store: false` (the
provider must not retain the content for distillation/evals) and `stream:
false`. It never sends `tools`, `tool_choice`, `response_format`,
`web_search_options`, `user`, `metadata` or `temperature`, so no request input
can widen it. Input is cut at `limits.summary_input_bytes` (default 64 KiB) on
a character boundary; the prompt says so and the result is `partial` with a
`truncated` warning. Status mapping: 401/403 authentication, 429 rate limited
without automatic replay, 400/404/413/422 invalid request, anything else
invalid response. Only a non-empty plain-text `choices[0].message.content`
is a summary; tool calls, refusals and empty messages are invalid responses.

Token billing is variable and the provider's error-billing contract is not
confirmed here, so the adapter uses `errors_are_unbilled: false` and sends
`request_micro_usd` as a per-request ceiling: settled in full on 2xx and held on
any error. The bounded input/output sizes make the ceiling a real bound the
operator can compute from the published token prices; nothing here asserts a
current OpenAI tariff and no live call has been made. The exact response JSON is
archived as an `HttpEntity` under `openai-chat-json/v1` and the generated text as
a distinct `Text` representation under `openai-summary/v1` in a new source whose
`provider` is `openai`; the summarized evidence is never modified and remains
readable without any provider. The summary is generated data (`generated:
true`, `untrusted: true`), never a quote of the source.

Spider implements the same `ScrapeProvider` trait, request contract and
evidence mapping with its own forced flags and billing rules; OpenAI implements
the separate `SummarizeProvider` trait. Each new adapter must follow
the same grant model, must not expand existing data grants or route around a
policy/access block, and must revalidate the provider's current API and billing
before implementation. A
provider failure only falls back to the next eligible
provider for unambiguous outcomes (unavailable, authentication, rate limited or
invalid response); cancellations, timeouts, egress/policy/access blocks and
budget limits are never replayed against another provider. Live provider calls
have not been run; current evidence uses local, synthetic responses.

## SearXNG (search, self-hosted)

SearXNG is the credential-less, self-hosted search adapter. Its instance origin
is operator configuration (`endpoint`, a bare public HTTPS origin with no path,
port, userinfo, query or fragment); the adapter always appends the fixed
`/search` path and only the documented parameters (`q`, `format=json`,
`safesearch=0`, `pageno=1`, and optionally `language` and `time_range`). It
deliberately does not send the undocumented, version-dependent `engines=`
parameter, and SearXNG has no country parameter, so an ISO alpha-2 `country` is
not forwarded. The adapter holds no credential and `request_micro_usd` defaults
to zero: the instance costs the operator, not the request.

The instance can be reached two mutually exclusive ways. A bare public HTTPS
`endpoint` goes through the mandatory egress proxy. Alternatively
`config.searxng_socket` (NixOS `services.secureResearch.searxng`) runs SearXNG
under its own UID and private network namespace, exposes it to the service on a
root:agent-research `0660` Unix socket, and routes its engine traffic through the
same egress proxy (`outgoing.proxies`); a bare `http://127.0.0.1` URL is still
refused by policy and is never a second network path.

The instance must enable the JSON format (`search.formats` must include `json`)
or it answers `403`, which the adapter maps to an unambiguous authentication
failure so another eligible search provider may run. The adapter treats an empty
`results` array with a non-empty `unresponsive_engines` list as
`ProviderUnavailable` rather than "no results", dedupes on the canonical URL,
re-sorts by SearXNG's numeric `score` (a missing or non-finite score is stable),
and caps at the requested count. Raw JSON and the normalized result data are
stored as separate representations (`searxng-http-json/v1`,
`searxng-web-search/v1`) exactly like the other search adapters. Live calls have
not been run; current evidence uses local, synthetic responses. A service/RPC
fixture verifies that a `429` retry cannot pass an exhausted job request/query
budget before its synthetic local transport records another send.
