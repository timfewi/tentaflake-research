# Deployment network-boundary component

`nix/network-boundary.nix` is an internal NixOS configuration fragment used by
the draft complete module. It takes explicit `serviceUid`, `egressUid` and
`vpnInterface` arguments plus `lib`, and an optional `vpnOuterMark` with its
`vpnOuterEndpoints`. It is not a
deployable service module:
`nixosModules.default` now assembles service/socket definitions, credentials,
filesystem views and aggregate resources. Full deployment verification and the
trusted VPN observation adapter remain outstanding.

The fragment rejects root, overlapping or invalid numeric UIDs and nonliteral,
loopback, wildcard or oversized interface names. Dedicated identities must not be
shared with unrelated host processes. The complete module must allocate and
cross-check them against client identities and the host user database.

## Rules and lifecycle

An independently owned `inet secure_research` table applies to both IPv4 and IPv6:

- Host-network packets from the service UID are dropped. The service still
  requires its own network namespace, where its internal loopback proxy can run.
- Egress-UID packets are dropped unless their output interface is exactly the
  configured VPN interface. The only optional exception is UDP carrying the
  explicitly configured mark of the trusted VPN's encrypted outer packets.
  This includes DNS and existing connections; there is no established/related
  bypass.
- The output hook checks at priority -10; postrouting rechecks at priority 300
  after output routing/mark changes and ordinary source NAT. Other chains' accept
  verdicts do not override these drops. The component does not grant traffic
  permission that another host policy denies.
- The egress unit requires, follows and binds to `nftables.service`. Reverse stop
  ordering is intended to stop egress before firewall teardown. Reloads use the
  pinned NixOS module's atomic ruleset update.

The intended invariant assumes the privileged host keeps this table installed,
reserves the configured interface for the VPN, and does not delegate raw packet,
network administration or UID-changing capabilities to research processes. The
full module must enforce those capabilities and independent namespace boundaries.
When `vpnOuterMark` is set, `vpnOuterEndpoints` must list the VPN peers (literal
IPv4/IPv6 address and UDP port, at most 16) and the two options are only valid
together. The host must reserve that nonzero 32-bit mark for the trusted VPN,
configure the VPN to set it on outer UDP packets, and avoid host rules that put
it on arbitrary egress traffic. Each endpoint becomes one rule that requires the
egress UID, a non-VPN output interface, the mark, the exact destination address
and the exact UDP port, so a marked packet to any other destination stays denied.
Research's egress identity must have neither `CAP_NET_ADMIN` nor `CAP_NET_RAW`,
which could allow `SO_MARK`. Without these options, all egress-UID packets
outside the VPN interface remain denied. WireGuard's outer UDP packets can inherit the inner socket UID, so an
unmarked WireGuard tunnel may be fail-closed but unusable for Research.
This fragment does not detect an encrypted tunnel, authenticate an exit, restrict
public destinations/ports by itself, or implement a VPN provider. URL/address,
port, DNS-answer and own-host-address policy remain in the Rust proxy. Readiness
comes from the separate trusted [observation contract](egress-control.md); the
evidence an adapter must observe is specified in [vpn-adapters.md](vpn-adapters.md).

## Current evidence

`checks.x86_64-linux.network-boundary` passes twenty-three pure configuration tests,
synthetic NixOS evaluation, service dependency assertions and the actual generated
`nft --check` through NixOS's LKL checker. It includes an independent permissive
host table. The exact VM fixture's rules and a marked variant with IPv4 and IPv6 endpoints also pass that syntax check. These are
configuration/syntax results, **not packet-confinement acceptance**.

`checks.x86_64-linux.network-boundary-vm` defines two isolated machines with two
network paths and synthetic TCP/UDP peers. The test first proves reachability,
then checks service denial, egress's allowed path, direct-path denial, IPv4/IPv6,
UDP port 53, permissive chains before/after the research chain, reload, marked
rerouting, simulated VPN-interface loss with direct fallback, and service stop
when the firewall stops. The VPN path is emulated by a dedicated interface, not
a real encrypted tunnel. The egress unit is a lifecycle probe, not the proxy;
full proxy/controller/worker deployment acceptance remains separate. UDP peers
echo synthetic packets on port 53; this checks the route, not DNS parsing.

The VM test **passed** after fetching its pinned binary-cache dependencies.
The old 2,709-derivation offline attempt is superseded. Initial runtime failures
were in the UDP fixture: the forking peer failed successive clients, and a
wildcard socket selected a different source address on fallback. The test-only
datagram server now uses stable per-destination sockets; all original path
assertions pass without firewall changes. The final script completed in about
41 seconds. No host firewall was loaded or VPN configuration inspected.
QEMU, the Python test driver and synthetic UDP peer are test dependencies only;
they are not part of the Research runtime or the consumer runtime builder.

`checks.x86_64-linux.network-boundary-wireguard-vm` passes with two disposable
machines and a real WireGuard tunnel. The guests generate private keys under
`/run` at test time. Root can use the direct path; the service UID is denied;
the egress UID reaches the peer only through `wg0` with the trusted outer mark.
The egress UID cannot set `SO_MARK` in the VM but can bind a socket to `wg0`.
The packaged `research-egress` accepts an HTTP request from the service UID
through its activated Unix socket and receives a response from a synthetic
upstream reachable only through `wg0`. A root-written synthetic Ready lease
enables this test path; it does not exercise the observer or controller. A
capture on the physical underlay contains WireGuard UDP packets but neither
synthetic inner payload nor the upstream response marker. Bringing that
underlay down breaks the proxy request and tunnel traffic while root still
reaches the other physical path and the egress UID remains denied there.
Stopping nftables stops both the proxy and the separate lifecycle probe. A
test-only mangle rule, present only for one block, marks datagrams from the
egress UID as a stand-in for a misapplied mark. A marked datagram to the exact
configured endpoint address and port is sent; the same marked datagrams to
another physical host and to the endpoint address on another port fail with
`EPERM` and never reach a listener there, while an unmarked root datagram to
that listener arrives. With the previous unrestricted marked-UDP rule this block
fails (`sent`, and the payload arrives), so it detects a regression. This proves
the marked-tunnel firewall and proxy data path in a synthetic VM, not the
deployed VPN, observer, complete service or agent harness.

See [development.md](development.md) for commands. Review the current verification matrix before relying on deployment claims.
