# Internal deployment fragment. Import only for an enabled Research deployment;
# this is not a standalone replacement for filesystem/socket/cgroup isolation.
{
  lib,
  serviceUid,
  egressUid,
  vpnInterface,
  vpnOuterMark ? null,
  vpnOuterEndpoints ? [ ],
}:
let
  validated =
    assert lib.assertMsg (
      builtins.isInt serviceUid && serviceUid > 0 && serviceUid < 4294967295
    ) "Research service UID must be an explicit non-root numeric UID";
    assert lib.assertMsg (
      builtins.isInt egressUid && egressUid > 0 && egressUid < 4294967295
    ) "Research egress UID must be an explicit non-root numeric UID";
    assert lib.assertMsg (serviceUid != egressUid) "Research service and egress UIDs must differ";
    assert lib.assertMsg (
      builtins.isString vpnInterface
      && builtins.match "[a-zA-Z0-9_.+-]{1,15}" vpnInterface != null
      && !(builtins.elem vpnInterface [
        "lo"
        "all"
        "default"
      ])
    ) "Research VPN interface must be a literal non-loopback interface name";
    assert lib.assertMsg (
      vpnOuterMark == null
      || (builtins.isInt vpnOuterMark && vpnOuterMark > 0 && vpnOuterMark <= 4294967295)
    ) "Research VPN outer mark must be a nonzero 32-bit integer";
    assert lib.assertMsg (
      (vpnOuterMark == null) == (vpnOuterEndpoints == [ ])
    ) "Research VPN outer mark and outer endpoints must be configured together";
    assert lib.assertMsg (
      builtins.isList vpnOuterEndpoints
      && builtins.length vpnOuterEndpoints <= 16
      && builtins.all validEndpoint vpnOuterEndpoints
    ) "Research VPN outer endpoints must be at most 16 literal IPv4/IPv6 address and UDP port pairs";
    true;
  ipv4Octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  isIpv4 = address: builtins.match "(${ipv4Octet}\\.){3}${ipv4Octet}" address != null;
  isIpv6 = address: builtins.match "[0-9a-fA-F:]{2,39}" address != null && lib.hasInfix ":" address;
  validEndpoint =
    endpoint:
    builtins.isAttrs endpoint
    &&
      builtins.attrNames endpoint == [
        "address"
        "port"
      ]
    && builtins.isString endpoint.address
    && (isIpv4 endpoint.address || isIpv6 endpoint.address)
    && builtins.isInt endpoint.port
    && endpoint.port >= 1
    && endpoint.port <= 65535;
  # A trusted VPN marks its encrypted outer UDP packets. The unprivileged egress
  # process must not have CAP_NET_ADMIN or CAP_NET_RAW to forge the mark. Even a
  # marked packet may only reach the configured VPN endpoints, never an
  # arbitrary destination outside the tunnel.
  outerRule =
    endpoint:
    let
      family = if isIpv4 endpoint.address then "ip" else "ip6";
    in
    ''meta skuid ${toString egressUid} oifname != "${vpnInterface}" meta mark ${toString vpnOuterMark} ${family} daddr ${endpoint.address} udp dport ${toString endpoint.port} counter accept'';
  outerException = lib.concatMapStringsSep "\n" outerRule vpnOuterEndpoints;
  guard =
    assert validated;
    ''
      meta skuid ${toString serviceUid} counter drop
      ${outerException}
      meta skuid ${toString egressUid} oifname != "${vpnInterface}" counter drop
    '';
in
{
  networking.nftables = {
    enable = true;
    tables.secure_research = {
      family = "inet";
      # A separate base chain's drop cannot be overridden by another chain's
      # accept, including a host-wide direct-network exception. Do not add a
      # preceding established/related accept: old connections must fail closed.
      content = ''
        chain output {
          type filter hook output priority -10; policy accept;
          ${guard}
        }
        # Recheck the final interface after output marking/routing and SNAT.
        chain postrouting {
          type filter hook postrouting priority 300; policy accept;
          ${guard}
        }
      '';
    };
  };
  # Reverse stop ordering removes egress before the firewall is torn down.
  # The full module must provide the unit, fixed UID and capability restrictions.
  systemd.services.agent-research-egress = {
    requires = [ "nftables.service" ];
    after = [ "nftables.service" ];
    bindsTo = [ "nftables.service" ];
  };
}
