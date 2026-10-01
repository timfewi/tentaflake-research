{
  pkgs,
  nixpkgs,
  self,
}:
let
  inherit (pkgs) lib;
  client = self.packages.${pkgs.stdenv.hostPlatform.system}.research-client;
  policy = {
    services.secureResearch = {
      enable = true;
      serviceUid = 4201;
      egressUid = 4202;
      vpnInterface = "fixture-vpn";
      resolvers = [ "9.9.9.9" ];
      containerClients = {
        hermes-alpha.uid = 62001;
        zeroclaw-beta.uid = 62002;
      };
    };
    users.users.fixture = {
      uid = 4100;
      isNormalUser = true;
    };
    systemd.tmpfiles.rules = [ "d /run/research-vpn 0755 root root -" ];
  };
  evaluate =
    extra:
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.default
        policy
        {
          boot.isContainer = true;
          system.stateVersion = "26.05";
        }
        extra
      ];
    }).config;
  valid = evaluate { };
  failures =
    config: map (entry: entry.message) (lib.filter (entry: !entry.assertion) config.assertions);
  duplicate = evaluate {
    services.secureResearch.containerClients.zeroclaw-beta.uid = lib.mkForce 62001;
  };
  alias = evaluate {
    users.users.unrelated = {
      uid = 62001;
      isNormalUser = true;
    };
  };
  probe = pkgs.writeText "research-container-client-probe.py" ''
    import json
    import os
    import subprocess
    import sys
    import time

    assert os.getuid() == 4100
    assert not os.path.exists("/run/agent-research/socket")
    assert not os.path.exists("/run/tentaflake-research")
    child = subprocess.Popen(
        ["${client}/bin/research-client", "--socket", "/run/client/socket"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    def send(message):
        child.stdin.write(json.dumps(message) + "\n")
        child.stdin.flush()
    def receive(identifier):
        while True:
            line = child.stdout.readline()
            assert line, "client exited before response"
            response = json.loads(line)
            if response.get("id") == identifier:
                assert "error" not in response, response
                return response["result"]
    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "container-capability-fixture", "version": "1"}}})
        receive(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        if sys.argv[1] == "hold":
            print("ready", flush=True)
            time.sleep(90)
            sys.exit(0)
        if sys.argv[1] == "idle-start":
            # MCP frontend pings do not traverse the internal research RPC.
            # A healthy stdio client must survive a normal gap between tool calls.
            time.sleep(65)
        args = {"operation": "start" if sys.argv[1] in ("idle-start", "recover") else sys.argv[1]}
        if len(sys.argv) > 2:
            args["job_id"] = sys.argv[2]
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "research_job", "arguments": args}})
        result = receive(2)
        if sys.argv[1] == "recover":
            assert not result.get("isError", False), result
            print("ready", flush=True)
            while not os.path.exists("/run/recovery/resume"):
                time.sleep(0.1)
            # Keep the same stdio process and issue a new operation after the
            # host has killed and recovered the upstream research service.
            assert child.poll() is None
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "research_job", "arguments": {"operation": "start"}}})
            result = receive(3)
        print(json.dumps(result), flush=True)
        child.stdin.close()
        assert child.wait(timeout=10) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
  '';
in
assert failures valid == [ ];
assert lib.any (lib.hasInfix "distinct upstream client UIDs") (failures duplicate);
assert lib.any (lib.hasInfix "shared with other host users") (failures alias);
assert valid.systemd.services."tentaflake-research-hermes-alpha@".serviceConfig.PrivateNetwork;
assert
  valid.systemd.services."tentaflake-research-hermes-alpha@".serviceConfig.RestrictAddressFamilies
  == [ "AF_UNIX" ];
assert valid.systemd.sockets.tentaflake-research-hermes-alpha.socketConfig.MaxConnections == 4;
pkgs.testers.runNixOSTest {
  name = "research-container-client-identities";
  nodes.machine = {
    imports = [
      self.nixosModules.default
      policy
    ];
    virtualisation.memorySize = 1024;
    environment.systemPackages = [ pkgs.util-linux ];
  };
  testScript = ''
    import json
    import re

    start_all()
    for name in ["hermes-alpha", "zeroclaw-beta"]:
        machine.wait_for_unit(f"tentaflake-research-{name}.socket")
    machine.succeed("test $(stat -c %a /run/tentaflake-research) = 700")
    # The same unprivileged UID cannot reach either host capability directory.
    machine.fail("setpriv --reuid=4100 --regid=users --clear-groups test -S /run/tentaflake-research/hermes-alpha/socket")
    machine.fail("setpriv --reuid=4100 --regid=users --clear-groups test -S /run/tentaflake-research/zeroclaw-beta/socket")

    def call(name, operation, job=None):
        suffix = "" if job is None else " " + job
        result = machine.succeed(
            "systemd-run --quiet --wait --pipe --collect "
            "-p User=fixture -p PrivateNetwork=yes -p ProtectHome=yes "
            "-p ProtectSystem=strict -p RuntimeMaxSec=120 "
            "-p TemporaryFileSystem=/run "
            f"-p BindReadOnlyPaths=/run/tentaflake-research/{name}:/run/client "
            f"${pkgs.python3}/bin/python3 ${probe} {operation}{suffix}"
        )
        return json.loads(result)

    a = call("hermes-alpha", "start")
    b = call("zeroclaw-beta", "start")
    assert not a.get("isError", False), a
    assert not b.get("isError", False), b
    job_a = a["structuredContent"]["job"]["id"]
    job_b = b["structuredContent"]["job"]["id"]
    assert re.fullmatch(r"[a-f0-9-]{36}", job_a), job_a
    assert re.fullmatch(r"[a-f0-9-]{36}", job_b), job_b
    # Both containers used UID 4100. The relay's host UID still owns each job.
    assert not call("hermes-alpha", "status", job_a).get("isError", False)
    assert not call("zeroclaw-beta", "status", job_b).get("isError", False)
    assert call("zeroclaw-beta", "status", job_a).get("isError", False)
    assert call("hermes-alpha", "status", job_b).get("isError", False)
    idle = call("hermes-alpha", "idle-start")
    assert not idle.get("isError", False), idle
    # Revocation stops already accepted relays, while the other client remains.
    machine.succeed(
        "systemd-run --quiet --collect --unit=relay-stop-fixture "
        "-p User=fixture -p PrivateNetwork=yes -p ProtectHome=yes "
        "-p ProtectSystem=strict -p RuntimeMaxSec=120 "
        "-p TemporaryFileSystem=/run "
        "-p BindReadOnlyPaths=/run/tentaflake-research/hermes-alpha:/run/client "
        "-p StandardOutput=file:/run/relay-stop-fixture-output "
        "${pkgs.python3}/bin/python3 ${probe} hold"
    )
    machine.wait_until_succeeds("grep -Fx ready /run/relay-stop-fixture-output")
    machine.succeed("systemctl list-units --state=running --no-legend 'tentaflake-research-hermes-alpha@*.service' | grep -q service")
    machine.succeed("systemctl stop tentaflake-research-hermes-alpha.socket")
    machine.wait_until_fails("systemctl list-units --state=running --no-legend 'tentaflake-research-hermes-alpha@*.service' | grep -q service")
    machine.succeed("systemctl is-active --quiet tentaflake-research-zeroclaw-beta.socket")
    assert not call("zeroclaw-beta", "status", job_b).get("isError", False)
    machine.succeed("systemctl stop relay-stop-fixture.service")
    machine.wait_for_unit("agent-research.service")

    with subtest("same stdio client reconnects after upstream service crash"):
        machine.succeed(
            "mkdir -p /run/research-recovery-fixture; "
            "systemd-run --quiet --unit=research-recovery-fixture "
            "-p User=fixture -p PrivateNetwork=yes -p ProtectHome=yes "
            "-p ProtectSystem=strict -p RuntimeMaxSec=120 "
            "-p TemporaryFileSystem=/run "
            "-p 'BindReadOnlyPaths=/run/tentaflake-research/zeroclaw-beta:/run/client "
            "/run/research-recovery-fixture:/run/recovery' "
            "-p StandardOutput=file:/run/research-recovery-output "
            "${pkgs.python3}/bin/python3 ${probe} recover"
        )
        machine.wait_until_succeeds("grep -Fx ready /run/research-recovery-output")
        old_pid = int(machine.succeed("systemctl show -p MainPID --value agent-research.service").strip())
        assert old_pid > 0
        machine.succeed(f"kill -9 {old_pid}")
        machine.wait_until_succeeds(
            "systemctl is-active --quiet agent-research.service && "
            f"test $(systemctl show -p MainPID --value agent-research.service) -ne {old_pid}"
        )
        machine.succeed("touch /run/research-recovery-fixture/resume")
        machine.wait_until_succeeds("grep -q '^{' /run/research-recovery-output")
        recovered = json.loads(machine.succeed("tail -n 1 /run/research-recovery-output"))
        assert not recovered.get("isError", False), recovered
        machine.wait_until_succeeds(
            "test $(systemctl show -p ActiveState --value research-recovery-fixture.service) = inactive"
        )
        machine.succeed("test $(systemctl show -p Result --value research-recovery-fixture.service) = success")
  '';
}
