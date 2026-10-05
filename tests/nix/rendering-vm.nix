# Full deployed parser/browser path against peers on an isolated test VLAN.
{
  pkgs,
  self,
  withParserProbe ? false,
}:
let
  client = self.packages.${pkgs.stdenv.hostPlatform.system}.research-client;
  servicePackage = self.packages.${pkgs.stdenv.hostPlatform.system}.research-service;
  # Test-only executable interposition: the production launcher constructs the
  # namespace unchanged, this guard runs inside it, then execs the real parser.
  checkedParser = pkgs.writeShellScript "research-checked-parser" ''
    set -eu
    test -r /input
    test -r /worker-config.json
    test -d /output
    test -d /tmp
    test ! -v CREDENTIALS_DIRECTORY
    for path in \
      /run/credentials/agent-research.service/provider-brave \
      /run/fixture-credentials/brave \
      /var/lib/agent-research/budget.sqlite \
      /run/agent-research/socket \
      /run/agent-research-egress/socket \
      /nix/var/nix/daemon-socket/socket; do
      test ! -e "$path"
      # Attempt a real read-open as well as metadata checks; never print data.
      if (exec 3<"$path") 2>/dev/null; then
        exit 97
      fi
      for root in /proc/[0-9]*/root; do
        test ! -e "$root$path"
        if (exec 3<"$root$path") 2>/dev/null; then
          exit 98
        fi
      done
    done
    exec ${servicePackage}/bin/research-worker "$@"
  '';
  parserProbePackage = pkgs.runCommand "research-parser-boundary-fixture" { } ''
    mkdir -p "$out/bin"
    ln -s ${servicePackage}/bin/research-service "$out/bin/research-service"
    ln -s ${servicePackage}/bin/research-browser-worker "$out/bin/research-browser-worker"
    ln -s ${checkedParser} "$out/bin/research-worker"
  '';
  observation = pkgs.writeText "synthetic-research-observation.py" ''
    import json
    import os
    import time

    # Synthetic lease only: this fixture does NOT detect a real VPN exit. The
    # region is a fixed test value used to prove the D2 profile mapping reaches
    # the rendered session; it is not exit proof and promises no anonymity.
    while True:
        with open("/run/research-vpn/next.json", "w") as output:
            json.dump({"version": 1, "generation": "11111111-1111-4111-8111-111111111111",
                       "mode": "ready", "valid_until": int(time.time()) + 5,
                       "region": "DE"}, output)
        os.replace("/run/research-vpn/next.json", "/run/research-vpn/observation.json")
        time.sleep(0.5)
  '';
  page = pkgs.writeTextDir "index.html" ''
    <!doctype html><meta charset="utf-8"><title>Isolated evidence</title>
    <link rel="icon" href="data:,">
    <article><h1>Isolated evidence</h1><p>Original é 👩‍🔬 “quoted evidence”.</p></article>
    <script>
      const paragraph = document.createElement('p');
      paragraph.textContent = 'Rendered Ω “browser evidence”.';
      document.querySelector('article').append(paragraph);
      // Expose the effective browser profile (D2) in the rendered DOM. The
      // values come from the real session's locale, timezone override and
      // Accept-Language, so they prove the region-derived profile reached the
      // browser rather than only the Rust configuration.
      const profile = document.createElement('p');
      profile.textContent = navigator.language + '|' +
        Intl.DateTimeFormat().resolvedOptions().timeZone + '|' +
        navigator.languages.join(',');
      document.querySelector('article').append(profile);
    </script>
  '';
  probe = pkgs.writeText "research-rendering-probe.py" ''
    import json
    from pathlib import Path
    import subprocess
    import sys
    import time

    child = subprocess.Popen(
        ["${client}/bin/research-client", "--socket", "/run/agent-research/socket"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    sequence = 0
    def exchange(method, params):
        global sequence
        sequence += 1
        child.stdin.write(json.dumps({"jsonrpc": "2.0", "id": sequence,
                                     "method": method, "params": params}) + "\n")
        child.stdin.flush()
        while True:
            line = child.stdout.readline()
            assert line, "client exited before response"
            response = json.loads(line)
            if response.get("id") == sequence:
                assert "error" not in response, response
                return response["result"]
    def call(name, **arguments):
        result = exchange("tools/call", {"name": name, "arguments": arguments})
        assert not result.get("isError", False), result
        return result["structuredContent"]
    def read(source):
        return call("research_read", kind="source", source_id=source["id"],
                    representation_id=source["primary_representation"]["id"])["content"]
    try:
        exchange("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "rendering-fixture", "version": "1"}})
        child.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        child.stdin.flush()
        job = call("research_job", operation="start")["job"]["id"]
        fetched = call("research_fetch", job_id=job, mode="http",
                       urls=["http://page.example.test/"])
        # This short script-bearing page intentionally needs rendering. HTTP
        # extraction succeeds but must report incomplete JavaScript coverage.
        assert fetched["coverage"]["partial"] == 1, fetched
        assert fetched["items"][0]["error"] is None, fetched
        assert fetched["items"][0]["data"]["javascript_required"] is True, fetched
        original = fetched["items"][0]["data"]["source"]
        assert original["primary_representation"]["kind"] == "text", original
        text = read(original)
        assert 'Original é 👩‍🔬 “quoted evidence”.' in text, text
        assert 'Rendered Ω' not in text, text
        opened = call("research_browser", action="open", job_id=job,
                      url="http://page.example.test/")
        rendered = opened["source"]
        text = read(rendered)
        assert 'Original é 👩‍🔬 “quoted evidence”.' in text, text
        assert 'Rendered Ω “browser evidence”.' in text, text
        # D2: the synthetic observed region DE must yield the coherent
        # de-DE / Europe/Berlin / de-DE,de;q=0.9,en;q=0.8 profile and reach the
        # real browser. The page reports navigator.language, the resolved IANA
        # timezone and the Accept-Language-derived navigator.languages list. This
        # pinned Chromium exposes the q-weighted Accept-Language tokens in
        # navigator.languages, so the observed list starts with de-DE.
        effective_profile = 'de-DE|Europe/Berlin|de-DE,de;q=0.9,en;q=0.8'
        assert effective_profile in text, (effective_profile, text)
        assert rendered["id"] != original["id"]
        Path("/run/rendering-fixture/open").touch()
        deadline = time.monotonic() + 45
        while not Path("/run/rendering-fixture/release").exists():
            assert time.monotonic() < deadline, "VM observer did not release browser"
            time.sleep(0.1)
        if sys.argv[1:] in (["worker-crash"], ["worker-hang"]):
            started = time.monotonic()
            failed = exchange("tools/call", {"name": "research_browser", "arguments": {
                "action": "read", "job_id": job, "session_id": opened["session_id"]}})
            assert failed.get("isError") is True, failed
            if sys.argv[1] == "worker-hang":
                assert failed["structuredContent"]["error"] == "timeout", failed
                # Default 60-second browser operation plus bounded shutdown.
                assert 55 <= time.monotonic() - started <= 85
            else:
                # Maintenance may already have removed the failed session.
                assert failed["structuredContent"]["error"] in ("worker_failed", "not_found"), failed
            Path("/run/rendering-fixture/failed").touch()
            deadline = time.monotonic() + 30
            while not Path("/run/rendering-fixture/cleanup-confirmed").exists():
                assert time.monotonic() < deadline, "worker cleanup was not confirmed"
                time.sleep(0.1)
            recovered = call("research_browser", action="open", job_id=job,
                             url="http://page.example.test/")
            assert 'Rendered Ω “browser evidence”.' in read(recovered["source"])
            call("research_browser", action="close", job_id=job, session_id=recovered["session_id"])
        else:
            call("research_browser", action="close", job_id=job, session_id=opened["session_id"])
        call("research_job", operation="finish", job_id=job)
        child.stdin.close()
        assert child.wait(timeout=15) == 0
        Path("/run/rendering-fixture/done").touch()
        print("deployed HTTP parser and Chromium preserved distinct Unicode evidence "
              "and rendered the region-derived de-DE/Europe/Berlin profile")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
  '';
  networkProbe = pkgs.writeText "research-network-probe.py" ''
    import socket
    import struct

    with socket.socket() as peer:
        peer.settimeout(5)
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth1\0")
        peer.connect(("93.184.216.34", 80))
        peer.sendall(b"GET / HTTP/1.0\r\nHost: page.example.test\r\n\r\n")
        response = peer.recv(4096)
        assert b"200 OK" in response, response
    for kind in (1, 28):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.settimeout(5)
            query = struct.pack("!6H", 123, 256, 1, 0, 0, 0)
            query += b"\x04page\x07example\x04test\0" + struct.pack("!2H", kind, 1)
            peer.sendto(query, ("9.9.9.9", 53))
            response, _ = peer.recvfrom(4096)
            print("synthetic DNS", kind, response.hex(), flush=True)
            assert response[:2] == query[:2]
  '';
  activationProbe = pkgs.writeText "research-activation-peer-probe.py" ''
    import socket
    import struct

    with socket.socket(socket.AF_UNIX) as peer:
        peer.connect("/run/agent-research-egress/socket")
        pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == 0, (pid, uid, gid)
        print("activation listener peer is root, not the egress service UID", flush=True)
  '';
  kernelProbe = pkgs.writeText "research-kernel-write-probe.py" ''
    import errno
    import os
    import sys

    root = "/proc/" + str(int(sys.argv[1])) + "/root"
    # Positive access witness: a hidden/missing root must not pass the denial.
    with open(root + "/etc/research/config.json", "rb") as config:
        assert config.read(1) == b"{"
    for relative in ("/proc/sys/kernel/hostname", "/proc/sys/kernel/core_pattern",
                     "/proc/sysrq-trigger"):
        path = root + relative
        assert os.path.exists(path), path
        try:
            descriptor = os.open(path, os.O_WRONLY)
        except OSError as error:
            assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
        else:
            os.close(descriptor)  # Never write, even if the regression fails.
            raise AssertionError("kernel control unexpectedly writable: " + relative)
  '';
  browserBoundaryProbe = pkgs.writeText "research-browser-boundary-probe.py" ''
    import json
    import os
    from pathlib import Path
    import sys

    service = Path("/proc") / str(int(sys.argv[1]))
    expected = b"synthetic-rendering-key-not-a-real-credential"
    credential = "run/credentials/agent-research.service/provider-brave"
    assert (service / "root" / credential).read_bytes().strip() == expected
    worker_binary = Path("${
      self.packages.${pkgs.stdenv.hostPlatform.system}.research-service
    }/bin/research-browser-worker")
    processes = []
    workers = 0
    renderers = 0
    visible_browser_roots = 0
    for process in Path("/proc").iterdir():
        if not process.name.isdigit() or process == service:
            continue
        try:
            if (process / "cgroup").read_bytes() != (service / "cgroup").read_bytes():
                continue
            # Track every observed process in the service cgroup, including
            # launchers/helpers, not only the binaries whose roots we inspect.
            processes.append((process.name, (process / "stat").read_text().split(") ", 1)[1].split()[19]))
            executable = os.readlink(process / "exe")
            worker = os.path.samestat((process / "exe").stat(), worker_binary.stat())
            if worker:
                Path("/run/rendering-fixture/worker.json").write_text(json.dumps(processes[-1]))
            chromium = "/chromium" in executable and executable.endswith("/chromium")
            if not worker and not chromium:
                continue
            root = process / "root"
            try:
                # Chromium's inner sandbox can root itself in a helper's proc
                # directory which becomes unresolvable after that helper exits.
                list(root.iterdir())
            except ProcessLookupError:
                assert not worker
                print("sealed chromium root", os.readlink(root), flush=True)
            else:
                assert (root / "worker").is_file(), process.name
                assert (root / "scratch").is_dir(), process.name
                visible_browser_roots += int(chromium)
                for hidden in (credential, "run/fixture-credentials/brave",
                               "var/lib/agent-research", "run/agent-research-egress/socket",
                               "run/agent-research/socket", "nix/var/nix/daemon-socket", "home"):
                    assert not (root / hidden).exists(), (process.name, hidden)
                    assert not (root / "proc/1/root" / hidden).exists(), (process.name, hidden)
            environment = (process / "environ").read_bytes()
            assert expected not in environment
            assert b"CREDENTIALS_DIRECTORY=" not in environment
            for descriptor in (process / "fd").iterdir():
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                assert not any(forbidden in target for forbidden in (
                    "provider-brave", "/fixture-credentials/", "budget.sqlite",
                    "/run/agent-research-egress/socket", "/run/agent-research/socket")), process.name
            for namespace in ("pid", "net", "user"):
                assert os.readlink(process / "ns" / namespace) != os.readlink(service / "ns" / namespace)
            command = (process / "cmdline").read_bytes()
            assert b"--no-sandbox" not in command
            renderer = b"--type=renderer" in command
            if renderer:
                status = (process / "status").read_text()
                assert "NoNewPrivs:\t1" in status
                assert "Seccomp:\t2" in status
            workers += int(worker)
            renderers += int(renderer)
        except (FileNotFoundError, ProcessLookupError):
            # A Chromium helper may exit while enumerating; required live worker
            # and renderer counts below prevent a vacuous pass.
            continue
    assert workers == 1 and renderers >= 1 and visible_browser_roots >= 1, (workers, renderers, visible_browser_roots)
    Path("/run/rendering-fixture/processes.json").write_text(json.dumps(processes))
    print("live browser worker and renderer credential/root/namespace checks passed")
  '';
  cleanupProbe = pkgs.writeText "research-browser-cleanup-probe.py" ''
    import json
    import os
    from pathlib import Path
    import sys

    processes = json.loads(Path("/run/rendering-fixture/processes.json").read_text())
    assert processes
    for pid, started in processes:
        try:
            current = (Path("/proc") / pid / "stat").read_text().split(") ", 1)[1].split()[19]
        except FileNotFoundError:
            continue
        assert current != started, "observed browser process survived close"
    scratch = Path("/proc") / str(int(sys.argv[1])) / "root/tmp/research"
    assert scratch.is_dir()
    remaining = list(scratch.glob("browser-*"))
    if remaining:
        # Synthetic guest metadata only, bounded and without following symlinks
        # or reading browser contents. Retain the strict cleanup assertion.
        entries = []
        for workspace in remaining:
            for directory, directories, files in os.walk(workspace, followlinks=False):
                for name in ["."] + directories + files:
                    path = Path(directory) / name
                    try:
                        stat = path.lstat()
                    except FileNotFoundError:
                        continue
                    entries.append((str(path.relative_to(scratch)), oct(stat.st_mode), stat.st_uid, stat.st_gid))
                    if len(entries) >= 64:
                        break
                if len(entries) >= 64:
                    break
            if len(entries) >= 64:
                break
        print("remaining synthetic workspace metadata:", entries, flush=True)
    assert not remaining, "browser workspace survived close"
  '';
  signalWorker = pkgs.writeText "research-signal-observed-worker.py" ''
    import json
    import os
    from pathlib import Path
    import signal
    import sys
    import time

    assert sys.argv[1:] in (["kill"], ["stop"])
    pid, started = json.loads(Path("/run/rendering-fixture/worker.json").read_text())
    descriptor = os.pidfd_open(int(pid))
    try:
        process = Path("/proc") / pid
        assert (process / "stat").read_text().split(") ", 1)[1].split()[19] == started
        expected = Path("${
          self.packages.${pkgs.stdenv.hostPlatform.system}.research-service
        }/bin/research-browser-worker")
        assert os.path.samestat((process / "exe").stat(), expected.stat())
        signal.pidfd_send_signal(descriptor, signal.SIGKILL if sys.argv[1] == "kill" else signal.SIGSTOP)
        if sys.argv[1] == "stop":
            deadline = time.monotonic() + 2
            while "State:\tT" not in (process / "status").read_text():
                assert time.monotonic() < deadline, "worker did not enter stopped state"
                time.sleep(0.01)
    finally:
        os.close(descriptor)
  '';
in
pkgs.testers.runNixOSTest {
  name = if withParserProbe then "research-parser-credentials" else "research-rendering";
  nodes = {
    research = { lib, ... }: {
      imports = [ self.nixosModules.default ];
      virtualisation.memorySize = 4096;
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4 = {
        addresses = lib.mkForce [
          {
            address = "93.184.216.33";
            prefixLength = 24;
          }
        ];
        routes = [
          {
            address = "9.9.9.9";
            prefixLength = 32;
            via = "93.184.216.34";
          }
        ];
      };
      users.users.fixture = {
        uid = 4100;
        isNormalUser = true;
      };
      services.secureResearch = {
        enable = true;
        package = if withParserProbe then parserProbePackage else servicePackage;
        serviceUid = 4201;
        egressUid = 4202;
        clients.fixture = 4100;
        vpnInterface = "eth1";
        resolvers = [ "9.9.9.9" ];
        browser.enable = true;
        # D2: derive a coherent profile from the synthetic observed region.
        # The neutral policy is covered by the browser::profile unit tests.
        browser.profile = "exit_region";
        searchOrder = [ "brave" ];
        providers.brave = {
          enable = true;
          capabilities = [ "search" ];
          data = [ "queries" ];
          apiKeyFile = "/run/fixture-credentials/brave";
          requestMicroUsd = 5000;
        };
      };
      systemd.tmpfiles.rules = [
        "d /run/research-vpn 0755 root root -"
        "d /run/rendering-fixture 0700 fixture users -"
        "d /run/fixture-credentials 0700 root root -"
        "f /run/fixture-credentials/brave 0600 root root - synthetic-rendering-key-not-a-real-credential"
      ];
      # Synthetic proof only: this is not a trusted VPN observation adapter.
      systemd.services.fixture-observation = {
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-tmpfiles-setup.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${observation}";
      };
      environment.systemPackages = [
        pkgs.jq
        pkgs.util-linux
      ];
    };
    upstream = { lib, ... }: {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      # Public-looking addresses exist solely inside the isolated VLAN. No
      # private-address policy exceptions or external DNS/upstreams are used.
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = "93.184.216.34";
          prefixLength = 24;
        }
        {
          address = "9.9.9.9";
          prefixLength = 32;
        }
      ];
      services.dnsmasq = {
        enable = true;
        settings = {
          no-resolv = true;
          no-hosts = true;
          log-queries = true;
          host-record = "page.example.test,93.184.216.34";
          local = "/example.test/";
          listen-address = "9.9.9.9";
        };
      };
      services.nginx = {
        enable = true;
        virtualHosts."page.example.test" = {
          root = page;
          locations."= /robots.txt".return = "200 'User-agent: *\\nAllow: /\\n'";
        };
      };
    };
  };
  testScript = ''
    start_all()
    upstream.wait_for_unit("nginx.service")
    upstream.wait_for_unit("dnsmasq.service")
    upstream.wait_for_unit("network-addresses-eth1.service")
    research.wait_for_unit("network-addresses-eth1.service")
    research.succeed("setpriv --reuid=4202 --regid=4202 --clear-groups ${pkgs.python3}/bin/python3 ${networkProbe}")
    research.wait_for_unit("agent-research.socket")
    print(research.succeed("${pkgs.python3}/bin/python3 ${activationProbe}"))
    research.wait_until_succeeds("jq -e '.mode == \"ready\"' /run/agent-research-egress/control/state.json")
    def open_observed_session(unit, mode=""):
        # Only named fixture synchronization/observation files are removed.
        research.succeed("rm -f /run/rendering-fixture/open /run/rendering-fixture/release /run/rendering-fixture/done /run/rendering-fixture/processes.json /run/rendering-fixture/worker.json /run/rendering-fixture/failed /run/rendering-fixture/cleanup-confirmed")
        research.succeed(f"systemd-run --unit={unit} -p User=fixture -p SupplementaryGroups=agent-research-clients -p RuntimeMaxSec=180 ${pkgs.python3}/bin/python3 ${probe} {mode}")
        research.wait_until_succeeds("test -f /run/rendering-fixture/open", timeout=90)
        pid = research.succeed("systemctl show -p MainPID --value agent-research.service").strip()
        assert int(pid) > 0
        print(research.succeed(f"${pkgs.python3}/bin/python3 ${browserBoundaryProbe} {pid}"))
        return pid

    def require_cleanup(pid, timeout=15):
        # On residue, print a bounded service journal window for cause analysis,
        # then re-raise so the strict cleanup assertion itself is unchanged.
        try:
            research.wait_until_succeeds(f"${pkgs.python3}/bin/python3 ${cleanupProbe} {pid}", timeout=timeout)
        except Exception:
            try:
                print(research.succeed("journalctl -u agent-research.service --no-pager -n 40"))
            except Exception as diagnostics:
                print("cleanup journal diagnostics unavailable:", diagnostics)
            raise

    def close_observed_session(pid):
        research.succeed("touch /run/rendering-fixture/release")
        research.wait_until_succeeds("test -f /run/rendering-fixture/done", timeout=30)
        require_cleanup(pid)

    close_observed_session(open_observed_session("rendering-normal"))
    for mode, action, deadline in (("worker-crash", "kill", 20), ("worker-hang", "stop", 90)):
        worker_service_pid = open_observed_session("rendering-" + mode, mode)
        research.succeed("${pkgs.python3}/bin/python3 ${signalWorker} " + action)
        research.succeed("touch /run/rendering-fixture/release")
        research.wait_until_succeeds("test -f /run/rendering-fixture/failed", timeout=deadline)
        # Prove cleanup before job finish, disconnect or a new session can help it.
        # The hung worker is never resumed or killed by test cleanup.
        require_cleanup(worker_service_pid)
        research.succeed(f"test $(systemctl show -p MainPID --value agent-research.service) = {worker_service_pid}")
        research.succeed("touch /run/rendering-fixture/cleanup-confirmed")
        research.wait_until_succeeds("test -f /run/rendering-fixture/done", timeout=30)
        require_cleanup(worker_service_pid)
    old_pid = open_observed_session("rendering-crash")
    # Kill only the real supervisor. systemd and the worker namespace lifecycle
    # must remove its descendants without help from this test or the client.
    research.succeed("systemctl kill --kill-whom=main --signal=SIGKILL agent-research.service")
    research.wait_until_succeeds(f"test $(systemctl show -p MainPID --value agent-research.service) -gt 0 && test $(systemctl show -p MainPID --value agent-research.service) != {old_pid}", timeout=45)
    research.wait_for_unit("agent-research.service")
    new_pid = research.succeed("systemctl show -p MainPID --value agent-research.service").strip()
    require_cleanup(new_pid)
    # Stop the now-orphaned test client only after descendant cleanup passed.
    research.succeed("systemctl stop rendering-crash.service")
    close_observed_session(open_observed_session("rendering-recovered"))
    research.succeed("systemctl is-active agent-research.service agent-research-egress.service")
    service_pid = research.succeed("systemctl show -p MainPID --value agent-research.service").strip()
    research.succeed(f"setpriv --reuid=4201 --regid=4201 --clear-groups ${pkgs.python3}/bin/python3 ${kernelProbe} {service_pid}")
  '';
}
