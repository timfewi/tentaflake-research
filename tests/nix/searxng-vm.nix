# Actual pinned SearXNG and supervisor inside the deployed private root/network.
# Egress remains offline: no live search engine or paid provider is contacted.
{ pkgs, self }:
let
  probe = pkgs.writeText "local-searxng-probe.py" ''
    import http.client
    import json
    import socket

    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.settimeout(40)
            self.sock.connect("/run/agent-research-searxng/socket")

    connection = Local("searxng.invalid", timeout=40)
    connection.request("GET", "/search?q=synthetic-fixture&format=json", headers={"Connection":"close"})
    response = connection.getresponse()
    assert response.status == 200, response.status
    body = response.read(1048577)
    assert len(body) <= 1048576
    result = json.loads(body)
    assert result["results"] == [], result
    failed = {entry[0] for entry in result["unresponsive_engines"]}
    assert failed == {"google", "brave", "duckduckgo", "bing"}, failed
    connection.close()
    print("Real local SearXNG JSON API works; all four engines fail closed offline")
  '';
in
pkgs.testers.runNixOSTest {
  name = "research-local-searxng";
  nodes.machine = {
    imports = [ self.nixosModules.default ];
    virtualisation.memorySize = 2048;
    users.users.fixture = {
      uid = 4100;
      isNormalUser = true;
    };
    services.secureResearch = {
      enable = true;
      serviceUid = 4201;
      egressUid = 4202;
      clients.fixture = 4100;
      vpnInterface = "fixture-vpn";
      resolvers = [ "9.9.9.9" ];
      searxng = {
        enable = true;
        uid = 4203;
      };
    };
    environment.systemPackages = [
      pkgs.python3
      pkgs.util-linux
      pkgs.iproute2
    ];
    # Deliberately absent observation file, but the operator-owned mount target
    # must exist so the controller can start and publish Offline readiness.
    systemd.tmpfiles.rules = [ "d /run/research-vpn 0755 root root -" ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("agent-research-searxng.socket")
    machine.succeed("timeout 50s setpriv --reuid=4201 --regid=4201 --clear-groups ${pkgs.python3}/bin/python ${probe}")
    machine.wait_for_unit("agent-research-searxng.service")
    pid = machine.succeed("systemctl show agent-research-searxng -p MainPID --value").strip()
    assert machine.succeed(f"readlink /proc/{pid}/ns/net") != machine.succeed("readlink /proc/1/ns/net")
    assert machine.succeed(f"nsenter -t {pid} -n ip -j route show default").strip() == "[]"
    for path in ["home", "run/credentials", "nix/var/nix/daemon-socket"]:
        machine.succeed(f"test ! -e /proc/{pid}/root/{path}")
    group = machine.succeed("systemctl show agent-research-searxng -p ControlGroup --value").strip()
    processes = machine.succeed(f"cat /sys/fs/cgroup{group}/cgroup.procs").split()
    # Require actual Gunicorn descendants, not just the Rust supervisor.
    assert pid in processes and len(processes) >= 3, processes
    # A client UID has no direct socket grant to local metasearch.
    machine.fail("timeout 5s setpriv --reuid=4100 --regid=users --clear-groups ${pkgs.python3}/bin/python ${probe}")
    machine.succeed("systemctl stop agent-research-searxng.service")
    for process in processes:
        machine.succeed(f"test ! -d /proc/{process}")
  '';
}
