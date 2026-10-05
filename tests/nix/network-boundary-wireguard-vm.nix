{ pkgs, self }:
let
  egress = self.packages.${pkgs.stdenv.hostPlatform.system}.research-egress;
  proxyConfig = pkgs.writeText "research-wireguard-proxy.json" (
    builtins.toJSON {
      socket_path = "/run/research-proxy/socket";
      control_file = "/run/research-test-control/state.json";
      allowed_peer_uids = [ 4001 ];
      vpn_interface = "wg0";
      resolvers = [ "9.9.9.9" ];
      denied_networks = [ ];
      max_connections = 4;
      connection_seconds = 10;
      connection_bytes = 1048576;
    }
  );
  httpServer = pkgs.writeText "research-wireguard-http.py" ''
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"synthetic-proxy-over-wireguard"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    ThreadingHTTPServer(("9.9.9.2", 80), Handler).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "research-network-boundary-wireguard";
  nodes = {
    research = { lib, ... }: {
      imports = [
        (import ../../nix/network-boundary.nix {
          inherit lib;
          serviceUid = 4001;
          egressUid = 4002;
          vpnInterface = "wg0";
          vpnOuterMark = 21063;
          vpnOuterEndpoints = [
            {
              address = "192.0.2.2";
              port = 51820;
            }
          ];
        })
      ];
      virtualisation.vlans = [
        1
        2
      ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = "192.0.2.1";
          prefixLength = 24;
        }
      ];
      networking.interfaces.eth2.ipv4.addresses = lib.mkForce [
        {
          address = "198.51.100.1";
          prefixLength = 24;
        }
      ];
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
        pkgs.wireguard-tools
        pkgs.socat
        pkgs.tcpdump
        pkgs.util-linux
        pkgs.python3
      ];
      # This probe retains the firewall lifecycle assertion alongside the real proxy below.
      systemd.services.agent-research-egress = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          User = "egress-test";
          ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
        };
      };
      systemd.sockets.research-proxy-test = {
        listenStreams = [ "/run/research-proxy/socket" ];
        socketConfig = {
          SocketUser = "root";
          SocketGroup = "research-test";
          SocketMode = "0660";
          DirectoryMode = "0755";
        };
      };
      systemd.services.research-proxy-test = {
        requires = [ "nftables.service" ];
        after = [ "nftables.service" ];
        serviceConfig = {
          User = "egress-test";
          Group = "egress-test";
          ExecStart = "${egress}/bin/research-egress --listen-fd 3 --config ${proxyConfig}";
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
          ];
        };
      };
      # The real observer and controller drive the proxy's readiness lease through
      # the actual tunnel; they are started by the test after the tunnel is up.
      systemd.services.research-vpn-observer.serviceConfig = {
        # The exit's public key is generated at test time and passed through this file.
        EnvironmentFile = "/run/research-vpn-observer.env";
        ExecStart = lib.concatStringsSep " " [
          "${egress}/bin/research-vpn-observer"
          "--interface wg0 --output /run/research-vpn/observation.json --refresh-seconds 1"
          "--region DE --firewall-marker /run/research-firewall/ready"
          "--link-kind wireguard --egress-uid 4002 --dns-resolver 9.9.9.9"
          "--handshake-within 190 --peer-public-key \${PEER_KEY}"
          "--drain-marker /run/research-vpn-drain/marker"
        ];
      };
      systemd.services.research-egress-control-test.serviceConfig.ExecStart = lib.concatStringsSep " " [
        "${egress}/bin/research-egress-control"
        "--input /run/research-vpn/observation.json"
        "--output /run/research-test-control/state.json --drain-seconds 20"
      ];
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
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = "192.0.2.2";
          prefixLength = 24;
        }
      ];
      networking.interfaces.eth2.ipv4.addresses = lib.mkForce [
        {
          address = "198.51.100.2";
          prefixLength = 24;
        }
      ];
      environment.systemPackages = [ pkgs.wireguard-tools ];
      systemd.services.echo = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:8080,reuseaddr,fork EXEC:${pkgs.coreutils}/bin/cat";
      };
      systemd.services.http-test.serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${httpServer}";
    };
  };
  testScript = ''
    import base64
    from datetime import timedelta
    import json
    import shlex

    start_all()
    research.wait_for_unit("agent-research-egress.service")
    upstream.wait_for_unit("echo.service")

    # Private keys exist only in the disposable guests' /run directories.
    for machine in [research, upstream]:
        machine.succeed("umask 077; wg genkey > /run/research-test-wg.key")
        machine.succeed("ip link add wg0 type wireguard")
    research_key = research.succeed("wg pubkey < /run/research-test-wg.key").strip()
    upstream_key = upstream.succeed("wg pubkey < /run/research-test-wg.key").strip()
    research.succeed("ip addr add 10.23.0.1/24 dev wg0")
    upstream.succeed("ip addr add 10.23.0.2/24 dev wg0")
    research.succeed("ip addr add 9.9.9.1/24 dev wg0")
    upstream.succeed("ip addr add 9.9.9.2/24 dev wg0")
    research.succeed("wg set wg0 fwmark 21063")
    research.succeed(
        "wg set wg0 listen-port 51820 private-key /run/research-test-wg.key "
        f"peer {shlex.quote(upstream_key)} allowed-ips 10.23.0.2/32,9.9.9.2/32 "
        "endpoint 192.0.2.2:51820 persistent-keepalive 1"
    )
    upstream.succeed(
        "wg set wg0 listen-port 51820 private-key /run/research-test-wg.key "
        f"peer {shlex.quote(research_key)} allowed-ips 10.23.0.1/32,9.9.9.1/32 "
        "endpoint 192.0.2.1:51820 persistent-keepalive 1"
    )
    research.succeed("ip link set wg0 up")
    upstream.succeed("ip link set wg0 up")
    upstream.succeed("systemctl start http-test.service")

    def probe(address, uid=None, marker="RESEARCH_WG_INNER_MARKER"):
        command = f"printf {shlex.quote(marker)} | timeout 3s socat -T1 - TCP4:{address}:8080"
        if uid is not None:
            command = f"setpriv --reuid={uid} --regid={uid} --clear-groups ${pkgs.bash}/bin/bash -c {shlex.quote(command)}"
        return f'test "$({command})" = {shlex.quote(marker)}'

    def publish_ready():
        now = int(research.succeed("date +%s").strip())
        state = json.dumps({
            "version": 1,
            "generation": "11111111-1111-4111-8111-111111111111",
            "mode": "ready",
            "valid_until": now + 9,
        })
        research.succeed(
            f"printf %s {shlex.quote(state)} > /run/research-test-control/state.tmp "
            "&& chmod 0644 /run/research-test-control/state.tmp "
            "&& mv /run/research-test-control/state.tmp /run/research-test-control/state.json"
        )

    def state():
        return json.loads(research.succeed("cat /run/research-test-control/state.json"))

    def diagnose():
        for command in [
            "uname -r",
            "ip rule",
            "ip route show table all",
            "ip -6 rule",
            "cat /sys/class/net/wg0/statistics/rx_packets /sys/class/net/wg0/uevent",
            "wg show wg0 transfer",
            "journalctl -u research-vpn-observer -u research-egress-control-test --no-pager -n 12",
            "cat /run/research-test-control/state.json /run/research-vpn/observation.json",
        ]:
            print("DIAG", command, "->", research.execute(command)[1])

    def wait_mode(mode, timeout=20):
        pattern = shlex.quote('"mode":"%s"' % mode)
        try:
            research.wait_until_succeeds(
                "grep -q " + pattern + " /run/research-test-control/state.json",
                timeout=timedelta(seconds=timeout),
            )
        except Exception:
            diagnose()
            raise

    request = b"GET http://9.9.9.2/ HTTP/1.1\r\nHost: 9.9.9.2\r\nConnection: close\r\n\r\n"
    encoded = base64.b64encode(request).decode()
    command = f"printf %s {encoded} | base64 -d | timeout 5s socat - UNIX-CONNECT:/run/research-proxy/socket"
    proxy_client = f"setpriv --reuid=4001 --regid=4001 --clear-groups ${pkgs.bash}/bin/bash -c {shlex.quote(command)}"
    proxy_probe = f"{proxy_client} | grep -q synthetic-proxy-over-wireguard"

    mark_probe = "python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 21063)'"
    research.succeed(mark_probe)
    research.fail(
        f"setpriv --reuid=4002 --regid=4002 --clear-groups ${pkgs.bash}/bin/bash -c {shlex.quote(mark_probe)}"
    )
    bind_probe = "python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b\"wg0\" + bytes(1))'"
    research.succeed(bind_probe)
    research.succeed(
        f"setpriv --reuid=4002 --regid=4002 --clear-groups ${pkgs.bash}/bin/bash -c {shlex.quote(bind_probe)}"
    )

    # Root can use the direct path despite permissive host nftables chains.
    research.wait_until_succeeds(probe("198.51.100.2"))
    research.fail(probe("198.51.100.2", 4002))
    research.fail(probe("198.51.100.2", 4001))

    research.succeed("systemd-run --unit=research-capture --collect tcpdump -U -i eth1 -w /tmp/research-wg.pcap udp port 51820")
    research.wait_for_unit("research-capture.service")
    research.wait_until_succeeds("test -s /tmp/research-wg.pcap")
    for uid in [None, 4002]:
        try:
            research.wait_until_succeeds(probe("10.23.0.2", uid), timeout=timedelta(seconds=12))
        except Exception:
            print("route:", research.succeed("ip route get 10.23.0.2"))
            print("egress route:", research.succeed("ip route get 10.23.0.2 uid 4002"))
            print("research tunnel bytes:", research.succeed("wg show wg0 transfer").split()[1:])
            print("upstream tunnel bytes:", upstream.succeed("wg show wg0 transfer").split()[1:])
            print("output rules:", research.succeed("nft list chain inet secure_research output"))
            print("postrouting rules:", research.succeed("nft list chain inet secure_research postrouting"))
            raise
    research.fail(probe("10.23.0.2", 4001))
    handshake = research.succeed("wg show wg0 latest-handshakes").strip().split()
    assert len(handshake) == 2 and int(handshake[1]) > 0

    # The trusted outer mark is not a general exit: even a marked datagram from
    # the egress UID may reach only the configured VPN endpoint address and port.
    # The unprivileged UID cannot set the mark itself, so this test-only mangle
    # rule stands in for a compromised marker. It exists only for this block.
    upstream.succeed(
        "systemd-run --unit=udp-negative --collect ${pkgs.bash}/bin/bash -c "
        "'exec ${pkgs.socat}/bin/socat -u UDP4-RECVFROM:9999,reuseaddr,fork OPEN:/tmp/udp-seen,creat,append'"
    )
    upstream.wait_until_succeeds("ss -uln | grep -q ':9999 '")

    def send_udp(uid, host, port, payload):
        code = (
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "try:\n"
            f"    s.sendto(b'{payload}', ('{host}', {port})); print('sent')\n"
            "except OSError as error:\n"
            "    print('blocked', error.errno)\n"
        )
        command = f"python3 -c {shlex.quote(code)}"
        if uid is not None:
            command = f"setpriv --reuid={uid} --regid={uid} --clear-groups ${pkgs.bash}/bin/bash -c {shlex.quote(command)}"
        return research.succeed(command).strip()

    # Control: root reaches the listener on the physical path, so the listener works.
    assert send_udp(None, "198.51.100.2", 9999, "ROOT_CONTROL") == "sent"
    upstream.wait_until_succeeds("grep -q ROOT_CONTROL /tmp/udp-seen")

    research.succeed(
        "nft -f - <<'EOF'\n"
        "table inet research_test_mark {\n"
        "  chain output {\n"
        "    type route hook output priority -150; policy accept;\n"
        "    meta skuid 4002 udp dport { 9999, 51820 } counter meta mark set 21063\n"
        "  }\n"
        "}\n"
        "EOF"
    )
    # Positive: a marked datagram to the exact endpoint address and port passes.
    assert send_udp(4002, "192.0.2.2", 51820, "MARKED_ENDPOINT") == "sent"
    # Negative: the same mark toward another physical host or another port is denied.
    other_host = send_udp(4002, "198.51.100.2", 9999, "MARKED_OTHER_HOST")
    other_port = send_udp(4002, "192.0.2.2", 9999, "MARKED_OTHER_PORT")
    print("marked non-endpoint sends:", other_host, other_port)
    counters = research.succeed("nft list chain inet research_test_mark output")
    hits = [int(word) for line in counters.splitlines() if "counter packets" in line for word in [line.split("counter packets")[1].split()[0]]]
    assert hits and hits[0] >= 3, counters
    upstream.succeed("sleep 2")
    upstream.fail("grep -q MARKED_ /tmp/udp-seen")
    research.succeed("nft delete table inet research_test_mark")
    # Make the tunnel the exit as wg-quick does: a default route in its own table
    # for unmarked traffic, with main (minus default routes) consulted first. The
    # outer WireGuard packets carry the mark and keep using the physical path.
    research.succeed(f"wg set wg0 peer {shlex.quote(upstream_key)} allowed-ips 0.0.0.0/0")
    research.succeed("ip route add default dev wg0 table 51820")
    research.succeed("ip rule add priority 32764 table main suppress_prefixlength 0")
    research.succeed("ip rule add priority 32765 not fwmark 21063 table 51820")
    # IPv6 has no tunnel here, and the node learns a physical IPv6 default route
    # from router advertisements: unmarked IPv6 traffic is blocked instead.
    research.succeed("ip -6 route add blackhole default table 51820")
    research.succeed("ip -6 rule add priority 32764 table main suppress_prefixlength 0")
    research.succeed("ip -6 rule add priority 32765 not fwmark 21063 table 51820")
    research.succeed(probe("10.23.0.2", 4002))
    research.succeed(probe("198.51.100.2"))
    research.fail(probe("198.51.100.2", 4002))

    # The actual observer and controller prove readiness from the real tunnel.
    research.succeed(
        "install -d -m 0755 /run/research-vpn /run/research-test-control "
        "/run/research-firewall /run/research-vpn-drain"
    )
    research.succeed("install -m 0644 /dev/null /run/research-firewall/ready")
    research.succeed(f"echo PEER_KEY={shlex.quote(upstream_key)} > /run/research-vpn-observer.env")
    research.succeed("systemctl start research-vpn-observer.service research-egress-control-test.service")
    wait_mode("ready", 30)
    assert state()["region"] == "DE", state()
    research.succeed("systemctl start research-proxy-test.socket")
    research.wait_until_succeeds(proxy_probe, timeout=timedelta(seconds=8))
    research.wait_for_unit("research-proxy-test.service")

    research.succeed("systemctl stop research-capture.service")
    packets = research.succeed("tcpdump -nn -r /tmp/research-wg.pcap 2>/dev/null").splitlines()
    assert len(packets) >= 2, packets
    research.fail("grep -a -q RESEARCH_WG_INNER_MARKER /tmp/research-wg.pcap")
    research.fail("grep -a -q synthetic-proxy-over-wireguard /tmp/research-wg.pcap")

    # Real kernel evidence: without the tunnel rule the direct main default would
    # win for the egress identity, so the exit is not ready until it is restored.
    ready_generation = state()["generation"]
    research.succeed("ip rule del priority 32765")
    wait_mode("offline")
    research.fail(proxy_probe)
    research.succeed("ip rule add priority 32765 not fwmark 21063 table 51820")
    wait_mode("ready")
    assert state()["generation"] != ready_generation
    # IPv6 must not leave through another interface either: without its blocking
    # rule the physical IPv6 default from router advertisements would win.
    research.succeed("ip -6 rule del priority 32765")
    wait_mode("offline")
    research.succeed("ip -6 rule add priority 32765 not fwmark 21063 table 51820")
    wait_mode("ready")

    # The exit is the pinned WireGuard peer: an additional peer is not the exit.
    stranger = research.succeed("wg genkey | wg pubkey").strip()
    research.succeed(f"wg set wg0 peer {shlex.quote(stranger)} allowed-ips 10.99.0.1/32")
    wait_mode("offline")
    research.succeed(f"wg set wg0 peer {shlex.quote(stranger)} remove")
    wait_mode("ready")

    # Losing the tunnel interface is offline at once; recovery is a new generation.
    tunnel_generation = state()["generation"]
    research.succeed("ip link set wg0 down")
    wait_mode("offline")
    research.fail(proxy_probe)
    research.succeed("ip link set wg0 up")
    research.succeed("ip route add default dev wg0 table 51820")
    wait_mode("ready", 30)
    assert state()["generation"] != tunnel_generation

    # A planned exit change drains the current generation and then starts a new one.
    drained_generation = state()["generation"]
    research.succeed("install -m 0644 /dev/null /run/research-vpn-drain/marker")
    wait_mode("draining")
    assert state()["generation"] == drained_generation
    research.succeed("rm -f /run/research-vpn-drain/marker")
    wait_mode("ready")
    assert state()["generation"] != drained_generation

    # A dead observer or controller never leaves the exit ready: the last lease
    # expires and new work is refused. A restarted process starts a new epoch.
    research.succeed("systemctl kill --signal=SIGKILL research-vpn-observer.service")
    wait_mode("offline", 25)
    research.fail(proxy_probe)
    research.succeed("systemctl start research-vpn-observer.service")
    wait_mode("ready", 30)
    research.wait_until_succeeds(proxy_probe, timeout=timedelta(seconds=8))
    research.succeed("systemctl kill --signal=SIGKILL research-egress-control-test.service")
    research.wait_until_fails(proxy_probe, timeout=timedelta(seconds=10))
    research.succeed("systemctl start research-egress-control-test.service")
    wait_mode("ready", 30)
    research.wait_until_succeeds(proxy_probe, timeout=timedelta(seconds=8))

    # Losing the tunnel's underlay is not seen by the observer until the last
    # handshake ages out (up to the 190 s window), so the firewall alone must
    # hold with a ready lease, even though root can still use the direct route.
    research.succeed("ip link set eth1 down")
    research.succeed("systemctl stop research-vpn-observer.service research-egress-control-test.service")
    publish_ready()
    research.fail(proxy_probe)
    research.fail(probe("10.23.0.2", 4002))
    research.succeed(probe("198.51.100.2"))
    research.fail(probe("198.51.100.2", 4002))
    research.succeed("systemctl stop nftables")
    research.wait_until_succeeds("test $(systemctl is-active agent-research-egress) = inactive")
    research.wait_until_succeeds("test $(systemctl is-active research-proxy-test) = inactive")
  '';
}
