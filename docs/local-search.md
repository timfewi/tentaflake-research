# Local SearXNG

Requested topology: client → Research → Tavily → Brave → local
SearXNG → Research egress → the operator's existing VPN/Mullvad exit.
Within SearXNG, DuckDuckGo is listed first, followed by Google, Brave and Bing.
Search preserves provider order and uses only explicitly granted providers.

## Deployment configuration

In the existing `services.secureResearch` configuration, use a distinct unused
numeric UID for SearXNG (4203 below is an example, not a host assignment):

```nix
services.secureResearch = {
  searxng = {
    enable = true;
    uid = 4203;
  };
  searchOrder = [
    "tavily"
    "brave"
    "searxng"
  ];
};
```

SearXNG alone needs neither a key nor a price. Tavily and Brave participate only
when the host explicitly grants them and supplies their runtime credentials;
otherwise the order resolves to SearXNG. Credentials stay in systemd's service
projection. The module supplies the local search grant and selects only SearXNG
by default; the mixed order above is an explicit host choice. Local mode cannot
also set a public `providers.searxng.endpoint`.
The existing service/client UID, VPN interface, resolvers and trusted observer
configuration remain required. This example is not host activation.

## Isolation

`research-searxng` supervises the pinned SearXNG package in a separate systemd
root and loopback-only network namespace, under its own identity. SearXNG is a
Python dependency in that separate service; the Research implementation remains
Rust. Only the selected package closures, public CA roots and internal runtime
sockets enter its root. It receives no provider credentials or personal files.
Its scratch tmpfs is bounded and it shares the aggregate Research resource slice.

Research connects to a root-owned Unix socket through a dedicated local-search
transport. An ordinary fetch or browser URL cannot select that transport.
The socket supervisor checks the peer UID and forwards only to the local SearXNG
process. Its outgoing proxy validates the egress peer and relays to the existing
egress socket. There is no direct DNS or Internet route. Egress rechecks public
destinations, current VPN readiness and the existing network boundary. An
additional host UID firewall guard protects against host direct exceptions.

SearXNG is configured with JSON output, four explicit engines, bounded engine
timeouts and no automatic outgoing retries. Engine request fan-out is bounded
by that fixed set and the egress connection caps; the Research query ledger
counts a metasearch operation, not individual engine subrequests. Child stdout
and stderr are not logged because they may contain queries or URLs.

Public engines can block or throttle VPN exits. No CAPTCHA, authentication or
network-policy bypass is added. Local SearXNG does not make searches offline or
anonymous. Actual engine availability must be verified separately.

## Budget incident

The supplied job had a 2,000,000-byte limit. The old HTTP transport reserved
the full per-response ceiling (up to 32 MiB for retrieval) before knowing the
response size. This could reject small documents before any I/O. The transport
now atomically clamps that ceiling to remaining job bytes, including outgoing
POST bytes and the overflow sentinel. Actual successful bytes are settled;
uncertain failures retain their conservative reservation. Simultaneous work
cannot reserve the same remaining bytes twice.

The previous `egress_unavailable` event is not explained by this byte-budget
fix. Fresh public documentation fetches succeeded on 2026-09-19 without paid
provider calls. That proves current HTTP retrieval, not historical root cause,
engine acceptance or a deployed SearXNG configuration.
