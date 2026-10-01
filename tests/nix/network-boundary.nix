{ pkgs, nixpkgs }:
let
  inherit (pkgs) lib;
  arguments = {
    inherit lib;
    serviceUid = 4001;
    egressUid = 4002;
    vpnInterface = "vpn-test0";
  };
  fragment = import ../../nix/network-boundary.nix;
  valid = fragment arguments;
  endpointV4 = {
    address = "192.0.2.2";
    port = 51820;
  };
  endpointV6 = {
    address = "2001:db8::2";
    port = 51821;
  };
  markedArguments = arguments // {
    vpnOuterMark = 21063;
    vpnOuterEndpoints = [
      endpointV4
      endpointV6
    ];
  };
  marked = fragment markedArguments;
  markedContent = marked.networking.nftables.tables.secure_research.content;
  rejectedWith =
    base: overrides: !(builtins.tryEval (builtins.deepSeq (fragment (base // overrides)) true)).success;
  rejected = rejectedWith arguments;
  rejectedMarked = rejectedWith markedArguments;
  failures = lib.runTests {
    testRootService = {
      expr = rejected { serviceUid = 0; };
      expected = true;
    };
    testRootEgress = {
      expr = rejected { egressUid = 0; };
      expected = true;
    };
    testSameIdentity = {
      expr = rejected { egressUid = 4001; };
      expected = true;
    };
    testNegativeUid = {
      expr = rejected { serviceUid = -1; };
      expected = true;
    };
    testOverflowUid = {
      expr = rejected { egressUid = 4294967295; };
      expected = true;
    };
    testStringUid = {
      expr = rejected { egressUid = "4002"; };
      expected = true;
    };
    testLoopback = {
      expr = rejected { vpnInterface = "lo"; };
      expected = true;
    };
    testWildcard = {
      expr = rejected { vpnInterface = "vpn*"; };
      expected = true;
    };
    testInjection = {
      expr = rejected { vpnInterface = "x\" accept"; };
      expected = true;
    };
    testEmptyInterface = {
      expr = rejected { vpnInterface = ""; };
      expected = true;
    };
    testLongInterface = {
      expr = rejected { vpnInterface = "1234567890123456"; };
      expected = true;
    };
    testZeroOuterMark = {
      expr = rejected { vpnOuterMark = 0; };
      expected = true;
    };
    testOverflowOuterMark = {
      expr = rejected { vpnOuterMark = 4294967296; };
      expected = true;
    };
    testStringOuterMark = {
      expr = rejected { vpnOuterMark = "21063"; };
      expected = true;
    };
    testMarkWithoutEndpoints = {
      expr = rejected { vpnOuterMark = 21063; };
      expected = true;
    };
    testEndpointsWithoutMark = {
      expr = rejected { vpnOuterEndpoints = [ endpointV4 ]; };
      expected = true;
    };
    testInvalidEndpointAddress = {
      expr =
        builtins.all
          (address: rejectedMarked { vpnOuterEndpoints = [ (endpointV4 // { inherit address; }) ]; })
          [
            "999.1.1.1"
            "192.0.2"
            "example.com"
            "192.0.2.2; drop"
            "12345"
            ""
          ];
      expected = true;
    };
    testInvalidEndpointPort = {
      expr =
        builtins.all (port: rejectedMarked { vpnOuterEndpoints = [ (endpointV4 // { inherit port; }) ]; })
          [
            0
            65536
            "51820"
          ];
      expected = true;
    };
    testExtraEndpointAttribute = {
      expr = rejectedMarked { vpnOuterEndpoints = [ (endpointV4 // { extra = true; }) ]; };
      expected = true;
    };
    testTooManyEndpoints = {
      expr = rejectedMarked { vpnOuterEndpoints = builtins.genList (_: endpointV4) 17; };
      expected = true;
    };
    testMarkedOuterUdpIsBoundToEndpoints = {
      expr =
        builtins.all (part: lib.hasInfix part markedContent) [
          "meta mark 21063 ip daddr 192.0.2.2 udp dport 51820 counter accept"
          "meta mark 21063 ip6 daddr 2001:db8::2 udp dport 51821 counter accept"
        ]
        && !(lib.hasInfix "meta mark 21063 counter accept" markedContent)
        && !(lib.hasInfix "meta mark 21063 meta l4proto udp" markedContent);
      expected = true;
    };
    testUnmarkedHasNoOuterException = {
      expr = !(lib.hasInfix "meta mark" valid.networking.nftables.tables.secure_research.content);
      expected = true;
    };
    testTwoFamilies = {
      expr = valid.networking.nftables.tables.secure_research.family;
      expected = "inet";
    };
  };
  fixtureFor =
    module:
    nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        module
        (_: {
          system.stateVersion = "26.05";
          # Synthetic general host exception must coexist, not replace our table.
          networking.nftables.tables.host_exception = {
            family = "inet";
            content = ''
              chain output { type filter hook output priority 100; policy accept; accept; }
            '';
          };
        })
      ];
    };
  inherit (fixtureFor valid) config;
  unit = config.systemd.services.agent-research-egress;
  # Building the real generated rules invokes NixOS's nft --check under LKL.
  rulesOf =
    configuration: builtins.elemAt configuration.systemd.services.nftables.serviceConfig.ExecStart 1;
  rules = rulesOf config;
  markedRules = rulesOf (fixtureFor marked).config;
in
assert lib.assertMsg (failures == [ ]) (builtins.toJSON failures);
assert config.networking.nftables.tables.secure_research.enable;
assert config.networking.nftables.tables.host_exception.enable;
assert builtins.elem "nftables.service" unit.requires;
assert builtins.elem "nftables.service" unit.after;
assert builtins.elem "nftables.service" unit.bindsTo;
pkgs.runCommand "research-network-boundary-evaluation"
  {
    inherit rules markedRules;
  }
  ''
    test -s "$rules"
    test -s "$markedRules"
    cp "$rules" "$out"
  ''
