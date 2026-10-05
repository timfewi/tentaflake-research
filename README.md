# tentaflake-research

An isolated public research service for AI agents, extracted from the MIT-licensed
`secure-research-tool`. One research service handles web search, public HTTP/PDF
retrieval, browser reading and saved evidence. Model requests stay with the
agent's separate LLM broker.

The five-tool interface stays provider-independent: search and scrape adapters
are optional operator-granted integrations, and retrieval does not require a
model provider. Domain-specific lead/contact workflows are outside this
infrastructure contract.

**Experimental.** This is security-sensitive software, not a claim of complete
isolation or prompt-injection protection. See [SECURITY.md](SECURITY.md) for the
threat model and [verification](docs/verification.md) for current evidence.

```text
agent -> secure-research-tool (stdio MCP) -> Unix socket -> research service
                                                       -> isolated parsers/browser
                                                       -> protected egress -> VPN -> public web
agent -> LLM broker -> model provider
```

The client has no HTTP transport and holds no provider keys. The service checks
job ownership and budgets; workers receive only their required files. Egress
checks every target and DNS answer and connects to a validated numeric address.
After a lost Unix session, new calls can reconnect; interrupted operations are
never replayed automatically. Explicit client close remains final.
The NixOS firewall restricts egress to the configured VPN, including established
connections. Missing readiness closes admission. Sources retain provenance,
hashes, raw evidence, coverage and truncation information.

## Use

```sh
nix run github:timfewi/tentaflake-research#research-client -- \
  --socket /run/agent-research/socket
```

The operator must first configure and deploy the service. Import
`nixosModules.default` and configure `services.secureResearch`; the option name
and binaries preserve compatibility with the original tool. It is disabled until
explicitly configured. [Operations](docs/operations.md) explains identities,
credentials, VPN readiness and container socket projection.

Register the client as the MCP server **`secure-research-tool`**:

```json
{
  "mcpServers": {
    "secure-research-tool": {
      "command": "/path/to/research-client",
      "args": ["--socket", "/run/agent-research/socket"]
    }
  }
}
```

This server exposes five operations: `research_job`, `research_search`,
`research_fetch`, `research_browser` and `research_read`. They share the same
policy boundary. See [the API](docs/api.md). The client package also provides
GET-only `research-curl`, which uses the same socket and policy.

`research-curl` is a restricted curl replacement, not full curl. It accepts
`-f`, `-s`, `-S`, `-L`, `-m`/`--max-time` and `--socket`, writes the body to
stdout (`research-curl -fsSL --max-time 25 URL > page.html`) and answers `--help`
and `--version` locally. An unsupported option such as `-D` or `-o` exits with
status 2 and a message that names only the option and states this contract.
Response headers are not retained; `research_fetch` and `research_read` report a
source's final URL and retrieval time. None of these paths opens the socket or
starts a job. A host that exposes it as `curl` should execute it unchanged: its
`--version` starts with `research-curl <version>`, and the wrapper must not
translate, drop or retry unsupported options, add headers or credentials, or fall
back to a direct network client. Agent guidance should prefer the exposed Research
MCP tools, read `curl --help` after an argument error and not treat deployment
logs as proof of a live-site check.

`research-client` is an independent, small package: it builds without service,
browser, HTTP/TLS, DNS, HTML-parser or SQLite dependencies. Both client binaries
retain the same five-tool protocol and Unix-socket transport. The service and
egress packages keep their existing outputs; real Research VM tests still need
the full service build.

Disable native web search, HTTP fetch and browser tools in the agent. Independently
deny direct IP egress and other network-capable MCP servers; a tool setting alone
does not restrict shell networking. Tentaflake's internal agent networks permit
only declared broker endpoints. The research socket grants web operations, not a
general proxy or access to provider credentials.

Paid search/scrape providers, OCR, Chromium and optional summarization require
explicit operator configuration. Fetching and evidence reads do not require an
LLM. No commercial provider is selected by default; inspect configured optional
adapters with `research_job` operation `providers`. [Providers](docs/providers.md) documents data grants and costs. The default
Tentaflake integration leaves research summarization disabled.

## Develop

```sh
nix develop --command cargo fetch --locked
nix develop --command project-check fast
nix build .#research-service .#research-client .#research-egress --no-link
```

The [development guide](docs/development.md) separates source checks from package,
namespace and VM tests. They use synthetic fixtures and require no paid-provider
keys or host activation.

[MIT](LICENSE). Original attribution is retained; [UPSTREAM.md](UPSTREAM.md)
records the source snapshot. This repository starts with fresh Git history and
does not contain deployment configuration or runtime state.
