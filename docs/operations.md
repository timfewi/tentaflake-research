# Operations

Import the flake's `nixosModules.default`. The compatibility namespace remains
`services.secureResearch`; enabling it requires explicit service and egress UIDs,
client identities, a VPN interface and public DNS resolvers. Select UIDs that do
not collide with other host users or groups. The module asserts these boundaries.

```nix
services.secureResearch = {
  enable = true;
  serviceUid = 4201;
  egressUid = 4202;
  clients.research-client = 61001;
  vpnInterface = "wg0";
  resolvers = [ "9.9.9.9" ];
};
users.users.research-client = {
  uid = 61001;
  isSystemUser = true;
  group = "research-client";
  extraGroups = [ "agent-research-clients" ];
};
users.groups.research-client = { };
```

This fragment does not configure a VPN or authorize paid providers. The operator
must supply trusted VPN readiness observations. The root lease controller checks
their freshness and generations; without them the service fails closed. The
optional reference observer requires an operator-owned firewall readiness marker.
See [egress-control.md](egress-control.md) and [network-boundary.md](network-boundary.md).

Provider keys stay in runtime credential files. Enabling a provider additionally
requires explicit capability/data grants and a cost ceiling; a key grants nothing
on its own. Research summarization stays off in the standard Tentaflake topology,
whose LLM requests use their own broker. Review [providers.md](providers.md) before
enabling optional cloud adapters.

The socket at `/run/agent-research/socket` is local and peer-UID authorized. Grant
the socket group only to permitted client sessions. Deny direct networking for
clients as well as disabling native web tools. A Unix socket mount is a capability:
project only the intended socket directory, never credentials, the host root or
unrelated service sockets.

For OCI clients declare `services.secureResearch.containerClients.NAME.uid` with
a distinct host UID for every agent. Project only
that relay's socket and the client's exact runtime closure into the container.
Its host socket is `/run/tentaflake-research/NAME/socket`. The root-only parent
protects each socket capability; only its selected child directory is projected.
The relay forwards through AF_UNIX with no IP networking. Shared internal
container UIDs then do not merge job ownership at the research service. Each
relay permits four connections, exits after 60 seconds idle or one hour total,
and shares the aggregate research slice limits. Restart the MCP client after
its relay connection closes. The container-client VM exercises cross-job refusal
with identical internal client UIDs.

Practical mode archives evidence with bounded retention; strict mode uses ephemeral
job content. Budget/accounting data remains persistent. Allocate disk headroom
beyond the content quota for SQLite/filesystem metadata and monitor failures.
The research slice caps aggregate memory/tasks and scratch; see
[resource-boundary.md](resource-boundary.md).

Stopping egress/firewall/VPN readiness must prevent new public requests. Preserve
the fail-closed unit dependencies when integrating with other service managers.
Validate actual packets and worker file access on the intended deployment before
treating it as production-ready.
