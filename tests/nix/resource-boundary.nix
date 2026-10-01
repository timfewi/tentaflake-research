{ pkgs, nixpkgs }:
let
  inherit (pkgs) lib;
  fragment = import ../../nix/resource-boundary.nix;
  resources = fragment {
    inherit lib;
    serviceUid = 4001;
  };
  fixture = nixpkgs.lib.nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      resources
      (import ../../nix/network-boundary.nix {
        inherit lib;
        serviceUid = 4001;
        egressUid = 4002;
        vpnInterface = "vpn-test0";
      })
      {
        system.stateVersion = "26.05";
        systemd.services =
          lib.genAttrs
            [
              "agent-research"
              "agent-research-egress"
              "agent-research-egress-control"
            ]
            (_: {
              serviceConfig.ExecStart = "${pkgs.coreutils}/bin/true";
            });
      }
    ];
  };
  inherit (fixture) config;
  service = config.systemd.services.agent-research.serviceConfig;
  slice = config.systemd.slices.agent-research.sliceConfig;
  units = map (name: config.systemd.services.${name}.serviceConfig) [
    "agent-research"
    "agent-research-egress"
    "agent-research-egress-control"
  ];
  invalidUid =
    uid:
    !(builtins.tryEval (
      builtins.deepSeq (fragment {
        inherit lib;
        serviceUid = uid;
      }) true
    )).success;
  failures = lib.runTests {
    testRootUid = {
      expr = invalidUid 0;
      expected = true;
    };
    testNegativeUid = {
      expr = invalidUid (-1);
      expected = true;
    };
    testStringUid = {
      expr = invalidUid "4001";
      expected = true;
    };
    testOverflowUid = {
      expr = invalidUid 4294967295;
      expected = true;
    };
    testSharedSlice = {
      expr = builtins.all (unit: unit.Slice == "agent-research.slice") units;
      expected = true;
    };
    testNoDelegation = {
      expr = builtins.all (unit: !unit.Delegate) units;
      expected = true;
    };
    testTreeShutdown = {
      expr = builtins.all (
        unit: unit.KillMode == "control-group" && unit.SendSIGKILL && unit.TimeoutStopSec == 30
      ) units;
      expected = true;
    };
    testNoCoreDumps = {
      expr = builtins.all (unit: unit.LimitCORE == 0) units;
      expected = true;
    };
    testMemoryBudget = {
      expr = slice.MemoryMax;
      expected = "2147483648";
    };
    testNoSwap = {
      expr = slice.MemorySwapMax;
      expected = "0";
    };
    testTaskBudget = {
      expr = slice.TasksMax;
      expected = 1024;
    };
    testSharedTemporaryBacking = {
      expr = service.TemporaryFileSystem;
      expected = [ "/tmp:rw,nosuid,nodev,noexec,size=536870912,mode=0700,uid=4001" ];
    };
    testNoSecondPrivateTmp = {
      expr = service.PrivateTmp;
      expected = false;
    };
    testServiceAlternativeTmpDenied = {
      expr = service.InaccessiblePaths;
      expected = [
        "/var/tmp"
        "/dev/shm"
      ];
    };
    testEgressTmpDenied = {
      expr = config.systemd.services.agent-research-egress.serviceConfig.InaccessiblePaths;
      expected = [
        "/tmp"
        "/var/tmp"
        "/dev/shm"
      ];
    };
    testControllerTmpDenied = {
      expr = config.systemd.services.agent-research-egress-control.serviceConfig.InaccessiblePaths;
      expected = [
        "/tmp"
        "/var/tmp"
        "/dev/shm"
      ];
    };
    testFirewallDependencyRetained = {
      expr = builtins.elem "nftables.service" config.systemd.services.agent-research-egress.bindsTo;
      expected = true;
    };
  };
  rendered = lib.genAttrs [
    "agent-research.slice"
    "agent-research.service"
    "agent-research-egress.service"
    "agent-research-egress-control.service"
    "nftables.service"
  ] (name: config.systemd.units.${name}.text);
  unitFiles = pkgs.linkFarm "research-resource-test-units" (
    lib.mapAttrsToList (name: text: {
      inherit name;
      path = pkgs.writeText name text;
    }) rendered
  );
in
assert lib.assertMsg (failures == [ ]) (builtins.toJSON failures);
pkgs.runCommand "research-resource-boundary-evaluation"
  {
    nativeBuildInputs = [ pkgs.systemd ];
    inherit unitFiles;
    renderedJson = pkgs.writeText "research-resource-units.json" (builtins.toJSON rendered);
  }
  ''
    # Restrict discovery to synthetic and immutable package units, not host config.
    export SYSTEMD_UNIT_PATH="$unitFiles:${pkgs.systemd}/example/systemd/system"
    export SYSTEMD_COLORS=0
    # User-manager parsing keeps manager scratch in the build sandbox rather than
    # creating /run/systemd on the host. This is syntax evidence, not activation.
    export XDG_RUNTIME_DIR="$TMPDIR/manager-runtime"
    mkdir -m 700 "$XDG_RUNTIME_DIR"
    systemd-analyze verify --user --man=no \
      "$unitFiles/agent-research.slice" \
      "$unitFiles/agent-research.service" \
      "$unitFiles/agent-research-egress.service" \
      "$unitFiles/agent-research-egress-control.service"
    cp "$renderedJson" "$out"
  ''
