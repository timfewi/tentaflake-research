# Real deployed binaries with offline egress; only optional synthetic credentials.
{
  pkgs,
  self,
  withCredentials ? false,
  withResources ? false,
}:
let
  system = pkgs.stdenv.hostPlatform.system;
  client = self.packages.${system}.research-client;
  memoryProbe = pkgs.writeText "research-memory-limit-probe.py" ''
    # Bounded at 2560 MiB even if the 2 GiB deployment cap regresses.
    chunks = []
    for _ in range(40):
        chunk = bytearray(64 * 1024 * 1024)
        for offset in range(0, len(chunk), 4096):
            chunk[offset] = 1
        chunks.append(chunk)
  '';
  taskProbe = pkgs.writeText "research-task-limit-probe.py" ''
    import errno
    import os
    import signal

    children = []
    refused = False
    try:
        # Fixed ceiling even if the deployment limit regresses.
        for _ in range(1100):
            try:
                pid = os.fork()
            except OSError as error:
                assert error.errno == errno.EAGAIN, error
                refused = True
                break
            if pid == 0:
                signal.pause()
                os._exit(0)
            children.append(pid)
        assert refused and len(children) > 0, "task admission was not bounded"
    finally:
        for pid in children:
            os.kill(pid, signal.SIGTERM)
        for pid in children:
            os.waitpid(pid, 0)
    print("task limit refused admission; all probe children reaped")
  '';
  # Python belongs solely to this synthetic test, never the product closure.
  probe = pkgs.writeText "research-mcp-probe.py" ''
    import json
    import subprocess

    child = subprocess.Popen(
        ["${client}/bin/research-client", "--socket", "/run/agent-research/socket"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    def send(message):
        child.stdin.write(json.dumps(message) + "\n")
        child.stdin.flush()
    def receive(identifier):
        while True:
            line = child.stdout.readline()
            assert line, "client exited before its response"
            response = json.loads(line)
            if response.get("id") == identifier:
                assert "error" not in response, response
                return response["result"]
    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "isolated-vm-fixture", "version": "1"}}})
        receive(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert {item["name"] for item in receive(2)["tools"]} == {
            "research_job", "research_search", "research_fetch",
            "research_browser", "research_read"}
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "research_job", "arguments": {"operation": "start"}}})
        result = receive(3)
        assert not result.get("isError", False), result
        child.stdin.close()
        assert child.wait(timeout=10) == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
  '';
in
pkgs.testers.runNixOSTest {
  name =
    if withResources then
      "research-module-resources"
    else if withCredentials then
      "research-module-credentials"
    else
      "research-module-offline";
  nodes.machine = {
    imports = [ self.nixosModules.default ];
    # Headroom above the 2 GiB slice cap prevents a guest-global OOM witness.
    virtualisation.memorySize = if withResources then 4096 else 1024;
    # Test instrumentation defaults to 2 (panic even for expected cgroup OOM).
    # Allow the resource fixture to observe the kill and subsequent recovery.
    boot.kernel.sysctl = pkgs.lib.optionalAttrs withResources { "vm.panic_on_oom" = 0; };
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
      searchOrder = pkgs.lib.optionals withCredentials [ "brave" ];
      providers = pkgs.lib.optionalAttrs withCredentials {
        brave = {
          enable = true;
          capabilities = [ "search" ];
          data = [ "queries" ];
          apiKeyFile = "/run/fixture-credentials/brave";
          requestMicroUsd = 5000;
        };
      };
    };
    # Missing observation is intentionally offline. The mount's secure parent
    # exists as it would for an operator-owned producer; no Ready proof is forged.
    systemd.tmpfiles.rules = [
      "d /run/research-vpn 0755 root root -"
    ]
    ++ pkgs.lib.optionals withCredentials [
      "d /run/fixture-credentials 0700 root root -"
      "f /run/fixture-credentials/brave 0600 root root - synthetic-test-key-not-a-real-credential"
    ];
    environment.systemPackages = [
      pkgs.jq
      pkgs.util-linux
    ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("agent-research.socket")
    machine.wait_for_unit("agent-research-egress-control.service")
    machine.wait_until_succeeds("jq -e '.mode == \"offline\"' /run/agent-research-egress/control/state.json")
    machine.succeed("grep -Fx 'Storage=volatile' /etc/systemd/journald@secure-research.conf")
    machine.succeed("grep -Fx 'RuntimeMaxUse=67108864' /etc/systemd/journald@secure-research.conf")
    machine.succeed("test $(systemctl show -p LogNamespace --value agent-research-egress-control.service) = secure-research")
    machine.succeed("test -z \"$(systemctl show -p LogsDirectory --value systemd-journald@secure-research.service)\"")
    machine.wait_until_succeeds("journalctl --namespace=secure-research --unit agent-research-egress-control.service --output=cat --no-pager | grep -q secure-research-diagnostic/v1")
    machine.fail("journalctl --unit agent-research-egress-control.service --output=cat --no-pager | grep -q secure-research-diagnostic/v1")
    machine.succeed("test $(stat -c %a /run/agent-research/socket) = 660")
    # An allowlisted UID without the session group still cannot open the socket.
    status, _ = machine.execute("timeout 15s setpriv --reuid=4100 --regid=users --clear-groups ${client}/bin/research-client --socket /run/agent-research/socket </dev/null")
    assert status == 1, f"expected client refusal, not timeout/setup failure: {status}"
    # A privileged client can open the socket, but root is not an allowed peer.
    status, _ = machine.execute("timeout 15s ${client}/bin/research-client --socket /run/agent-research/socket </dev/null")
    assert status == 1, f"expected peer refusal, not timeout/setup failure: {status}"
    machine.wait_for_unit("agent-research.service")
    # The only group grant belongs to this transient client session.
    machine.succeed("systemd-run --wait --pipe --collect -p User=fixture -p SupplementaryGroups=agent-research-clients -p RuntimeMaxSec=30 ${pkgs.python3}/bin/python3 ${probe}")
    machine.succeed("test -f /var/lib/agent-research/budget.sqlite")
    machine.succeed("test $(stat -c %a /var/lib/agent-research) = 700")
    machine.succeed("test $(systemctl show -p MemoryMax --value agent-research.slice) = 2147483648")
    machine.succeed("test $(systemctl show -p MemorySwapMax --value agent-research.slice) = 0")
    machine.succeed("systemctl stop agent-research.service")
    machine.succeed("test $(systemctl is-active agent-research.service) = inactive")
    # Fresh activation must reopen durable state and accept the permitted peer.
    machine.succeed("systemd-run --wait --pipe --collect -p User=fixture -p SupplementaryGroups=agent-research-clients -p RuntimeMaxSec=30 ${pkgs.python3}/bin/python3 ${probe}")
  ''
  + pkgs.lib.optionalString withResources ''
    service_pid = machine.succeed("systemctl show -p MainPID --value agent-research.service").strip()
    scratch = f"/proc/{service_pid}/root/tmp"
    assert int(service_pid) > 0
    machine.succeed(f"test $(stat -f -c %T {scratch}) = tmpfs")
    first = f"{scratch}/quota-witness-first"
    second = f"{scratch}/quota-witness-second"
    try:
        machine.succeed(f"fallocate -l 1048576 {first}")
        status, output = machine.execute(f"LC_ALL=C fallocate -l 536870912 {second} 2>&1")
        assert status != 0 and "No space left on device" in output, output
        machine.succeed("systemctl is-active agent-research.service")
    finally:
        machine.succeed(f"rm -f -- {first} {second}")
    # Capacity becomes available after cleanup, and MCP remains usable.
    machine.succeed(f"fallocate -l 1048576 {first} && rm -- {first}")
    group = machine.succeed("systemctl show -p ControlGroup --value agent-research.slice").strip()
    assert group.startswith("/") and ".." not in group
    group_path = f"/sys/fs/cgroup{group}"
    machine.succeed(f"test $(cat {group_path}/pids.max) = 1024")
    def task_refusals():
        events = machine.succeed(f"cat {group_path}/pids.events")
        return int(dict(line.split() for line in events.splitlines())["max"])
    before = task_refusals()
    # This extra test unit shares the deployed slice. Its own task cap is
    # unlimited, so the slice's kernel counter must witness the refusal.
    machine.succeed("systemd-run --wait --pipe --collect --unit=research-task-probe --slice=agent-research.slice -p TasksMax=infinity -p RuntimeMaxSec=60 ${pkgs.python3}/bin/python3 ${taskProbe}")
    assert task_refusals() > before, "refusal did not come from the Research slice"
    machine.wait_until_succeeds(f"test $(cat {group_path}/pids.current) -lt 64")
    machine.succeed(f"test $(cat {group_path}/memory.max) = 2147483648")
    machine.succeed(f"test $(cat {group_path}/memory.swap.max) = 0")
    def memory_events():
        events = machine.succeed(f"cat {group_path}/memory.events")
        return {key: int(value) for key, value in (line.split() for line in events.splitlines())}
    before_memory = memory_events()
    # Prefer this synthetic allocator as OOM victim, not the actual service.
    status, _ = machine.execute("systemd-run --wait --pipe --collect --unit=research-memory-probe --slice=agent-research.slice -p MemoryMax=infinity -p OOMScoreAdjust=1000 -p RuntimeMaxSec=60 ${pkgs.python3}/bin/python3 ${memoryProbe}")
    assert status != 0, "allocation exceeded the slice budget without refusal"
    after_memory = memory_events()
    assert after_memory["max"] > before_memory["max"]
    assert after_memory["oom_kill"] > before_memory["oom_kill"], "no slice OOM kill observed"
    machine.succeed("systemctl is-active agent-research.service")
    machine.succeed("systemd-run --wait --pipe --collect -p User=fixture -p SupplementaryGroups=agent-research-clients -p RuntimeMaxSec=30 ${pkgs.python3}/bin/python3 ${probe}")
  ''
  + pkgs.lib.optionalString withCredentials ''
    # Inspect only processes in this synthetic guest. Positive service startup
    # above proves Brave::from_credentials accepted the projected credential.
    service_pid = machine.succeed("systemctl show -p MainPID --value agent-research.service").strip()
    credential = "/run/credentials/agent-research.service/provider-brave"
    machine.succeed(f"cmp /run/fixture-credentials/brave /proc/{service_pid}/root{credential}")
    machine.succeed(f"test ! -e /proc/{service_pid}/root/run/fixture-credentials/brave")
    # A normal authorized client session must not receive either credential path.
    machine.succeed("systemd-run --wait --pipe --collect -p User=fixture -p SupplementaryGroups=agent-research-clients ${pkgs.bash}/bin/bash -c 'test ! -r /run/fixture-credentials/brave && test ! -r /run/credentials/agent-research.service/provider-brave'")
    machine.succeed("systemctl start agent-research-egress.service")
    for unit in ["agent-research-egress", "agent-research-egress-control"]:
        pid = machine.succeed(f"systemctl show -p MainPID --value {unit}.service").strip()
        assert int(pid) > 0
        machine.succeed(f"test ! -e /proc/{pid}/root{credential}")
        machine.succeed(f"test ! -e /proc/{pid}/root/run/fixture-credentials/brave")
    # Missing required credentials must fail closed, then recover once restored.
    # Only this VM's synthetic key is moved; no real account data is involved.
    machine.succeed("systemctl stop agent-research.service")
    machine.succeed("mv /run/fixture-credentials/brave /run/fixture-credentials/brave.saved")
    machine.execute("systemctl start agent-research.service")
    machine.wait_until_succeeds("test $(systemctl show -p Result --value agent-research.service) = exit-code")
    machine.succeed("systemctl stop agent-research.service")
    machine.succeed("mv /run/fixture-credentials/brave.saved /run/fixture-credentials/brave")
    machine.succeed("systemctl reset-failed agent-research.service")
    machine.succeed("systemd-run --wait --pipe --collect -p User=fixture -p SupplementaryGroups=agent-research-clients -p RuntimeMaxSec=30 ${pkgs.python3}/bin/python3 ${probe}")
  '';
}
