{ pkgs }:
let
  # Test-only datagram peer: fixed sockets serve successive clients without
  # per-peer child processes retaining the shared listening socket.
  udpEcho = pkgs.writeText "research-test-udp-echo.py" ''
    import select
    import socket
    import sys

    ipv6 = sys.argv[1] == "UDP6"
    servers = []
    for address in (["fd42:1::2", "fd42:2::2"] if ipv6 else ["192.0.2.2", "198.51.100.2"]):
        server = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
        if ipv6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        # Bind each destination so rerouted replies retain the requested source
        # address; connected UDP clients reject replies from another local IP.
        server.bind((address, 53))
        servers.append(server)
    while True:
        readable, _, _ = select.select(servers, [], [])
        for server in readable:
            data, peer = server.recvfrom(4096)
            server.sendto(data, peer)
  '';
in
pkgs.testers.runNixOSTest {
  name = "research-network-boundary";
  nodes = {
    research = { lib, ... }: {
      imports = [
        (import ../../nix/network-boundary.nix {
          inherit lib;
          serviceUid = 4001;
          egressUid = 4002;
          vpnInterface = "eth1";
        })
      ];
      virtualisation.vlans = [
        1
        2
      ];
      networking.firewall.enable = false;
      networking.interfaces.eth1 = {
        ipv4.addresses = lib.mkForce [
          {
            address = "192.0.2.1";
            prefixLength = 24;
          }
        ];
        ipv6.addresses = [
          {
            address = "fd42:1::1";
            prefixLength = 64;
          }
        ];
      };
      networking.interfaces.eth2 = {
        ipv4.addresses = lib.mkForce [
          {
            address = "198.51.100.1";
            prefixLength = 24;
          }
        ];
        ipv6.addresses = [
          {
            address = "fd42:2::1";
            prefixLength = 64;
          }
        ];
      };
      users.groups.research-test.gid = 4001;
      users.groups.egress-test.gid = 4002;
      users.users.research-test = {
        uid = 4001;
        group = "research-test";
        isSystemUser = true;
      };
      users.users.egress-test = {
        uid = 4002;
        group = "egress-test";
        isSystemUser = true;
      };
      environment.systemPackages = [
        pkgs.socat
        pkgs.util-linux
      ];
      # Lifecycle probe, not the real proxy. Real service isolation is a later gate.
      systemd.services.agent-research-egress = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          User = "egress-test";
          ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
        };
      };
      networking.nftables.tables.host_direct_exception = {
        family = "inet";
        content = ''
          chain before { type filter hook output priority -100; policy accept; accept; }
          chain after { type filter hook output priority 100; policy accept; accept; }
        '';
      };
    };
    upstream = { lib, ... }: {
      virtualisation.vlans = [
        1
        2
      ];
      networking.firewall.enable = false;
      networking.interfaces.eth1 = {
        ipv4.addresses = lib.mkForce [
          {
            address = "192.0.2.2";
            prefixLength = 24;
          }
        ];
        ipv6.addresses = [
          {
            address = "fd42:1::2";
            prefixLength = 64;
          }
        ];
      };
      networking.interfaces.eth2 = {
        ipv4.addresses = lib.mkForce [
          {
            address = "198.51.100.2";
            prefixLength = 24;
          }
        ];
        ipv6.addresses = [
          {
            address = "fd42:2::2";
            prefixLength = 64;
          }
        ];
      };
      systemd.services =
        lib.listToAttrs (
          map
            (transport: {
              name = "echo-${transport}";
              value = {
                wantedBy = [ "multi-user.target" ];
                serviceConfig.ExecStart = "${pkgs.socat}/bin/socat ${transport}-LISTEN:8080,reuseaddr,fork${lib.optionalString (lib.hasSuffix "6" transport) ",ipv6only=1"} EXEC:${pkgs.coreutils}/bin/cat";
              };
            })
            [
              "TCP4"
              "TCP6"
            ]
        )
        // lib.listToAttrs (
          map
            (transport: {
              name = "echo-${transport}";
              value = {
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];
                serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${udpEcho} ${transport}";
              };
            })
            [
              "UDP4"
              "UDP6"
            ]
        );
    };
  };
  testScript = ''
    import json
    import shlex

    start_all()
    research.wait_for_unit("agent-research-egress.service")
    for transport in ["TCP4", "TCP6", "UDP4", "UDP6"]:
        upstream.wait_for_unit(f"echo-{transport}.service")

    def probe(address, uid=None, udp=False):
        family = "6" if ":" in address else "4"
        destination = f"[{address}]" if family == "6" else address
        transport = ("UDP" if udp else "TCP") + family
        port = 53 if udp else 8080
        command = f"printf fixture | timeout 3s socat -T1 - {transport}:{destination}:{port}"
        if uid is not None:
            command = f"setpriv --reuid={uid} --regid={uid} --clear-groups ${pkgs.bash}/bin/bash -c {shlex.quote(command)}"
        return f'test "$({command})" = fixture'

    # Reachability is established first; negative checks cannot pass because
    # the synthetic server is missing. UDP port 53 checks DNS-path confinement,
    # not DNS message parsing (covered by separate Rust fixtures).
    for address in ["192.0.2.2", "198.51.100.2", "fd42:1::2", "fd42:2::2"]:
        for udp in [False, True]:
            research.wait_until_succeeds(probe(address, udp=udp))
            research.fail(probe(address, 4001, udp))
            if address in ["192.0.2.2", "fd42:1::2"]:
                research.succeed(probe(address, 4002, udp))
            else:
                research.fail(probe(address, 4002, udp))

    research.succeed("systemctl reload nftables")
    research.fail(probe("198.51.100.2", 4002))
    research.succeed(probe("192.0.2.2", 4002))

    # A host routing exception after the output check cannot move an allowed
    # packet onto the direct interface: the postrouting guard must drop it.
    research.succeed("ip route add table 100 192.0.2.2 via 198.51.100.2 dev eth2")
    research.succeed("ip rule add fwmark 1 table 100")
    research.succeed("nft add table inet reroute")
    research.succeed("nft 'add chain inet reroute output { type route hook output priority 50; policy accept; }'")
    research.succeed("nft add rule inet reroute output meta skuid 4002 meta mark set 1")
    research.fail(probe("192.0.2.2", 4002))
    counters = json.loads(research.succeed("nft -j list chain inet secure_research postrouting"))
    assert any(expression.get("counter", {}).get("packets", 0) > 0
               for item in counters["nftables"]
               for expression in item.get("rule", {}).get("expr", []))
    research.succeed("nft delete table inet reroute")
    research.succeed("ip rule del fwmark 1 table 100")

    # Simulated VPN-path loss and an explicit direct fallback to the same peer.
    research.succeed("ip link set eth1 down")
    research.succeed("ip route replace 192.0.2.2/32 via 198.51.100.2 dev eth2")
    research.succeed("ip -6 route replace fd42:1::2/128 via fd42:2::2 dev eth2")
    for address in ["192.0.2.2", "fd42:1::2"]:
        for udp in [False, True]:
            research.succeed(probe(address, udp=udp))
            research.fail(probe(address, 4002, udp))

    research.succeed("systemctl stop nftables")
    research.wait_until_succeeds("test $(systemctl is-active agent-research-egress) = inactive")
  '';
}
