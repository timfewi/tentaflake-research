{
  pkgs,
  nixpkgs,
  self,
}:
let
  inherit (pkgs) lib;
  fixturePackage =
    pkgs.runCommand "research-module-fixture" { meta.mainProgram = "research-service"; }
      ''
            mkdir -p "$out/bin"
        for name in research-service research-worker research-browser-worker research-egress research-egress-control research-searxng; do
              ln -s ${pkgs.coreutils}/bin/true "$out/bin/$name"
            done
      '';
  base = {
    system.stateVersion = "26.05";
    boot.isContainer = true;
    users.users.fixture = {
      uid = 4100;
      isNormalUser = true;
    };
  };
  evaluate =
    extra:
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.default
        base
        {
          services.secureResearch = {
            enable = true;
            package = fixturePackage;
            egressPackage = fixturePackage;
            serviceUid = 4201;
            egressUid = 4202;
            clients.fixture = 4100;
            vpnInterface = "vpn-test0";
            resolvers = [ "9.9.9.9" ];
          }
          // extra;
        }
      ];
    }).config;
  valid = evaluate { };
  outerEndpoint = {
    address = "192.0.2.2";
    port = 51820;
  };
  marked = evaluate {
    vpnOuterMark = 21063;
    vpnOuterEndpoints = [ outerEndpoint ];
  };
  logged = evaluate {
    logging.maxBytes = 8388608;
    logging.retentionDays = 3;
  };
  disabled =
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.default
        base
      ];
    }).config;
  rejected =
    overrides:
    let
      result = builtins.tryEval (builtins.all (item: item.assertion) (evaluate overrides).assertions);
    in
    !result.success || !result.value;
  service = valid.systemd.services.agent-research.serviceConfig;
  egress = valid.systemd.services.agent-research-egress.serviceConfig;
  control = valid.systemd.services.agent-research-egress-control.serviceConfig;
  journal = valid.environment.etc."systemd/journald@secure-research.conf".text;
  granted = evaluate {
    searchOrder = [ "brave" ];
    providers.brave = {
      enable = true;
      capabilities = [ "search" ];
      data = [ "queries" ];
      apiKeyFile = "/run/secrets/research-fixture-key";
      requestMicroUsd = 5000;
    };
    browser.enable = true;
  };
  openaiProvider = {
    enable = true;
    capabilities = [ "summarize" ];
    data = [ "content" ];
    apiKeyFile = "/run/secrets/research-fixture-openai";
    requestMicroUsd = 20000;
    model = "gpt-4o-mini";
  };
  summarized = evaluate {
    searchOrder = [ ];
    providers.openai = openaiProvider;
    summarizeOrder = [ "openai" ];
  };
  summaryService = summarized.systemd.services.agent-research.serviceConfig;
  localSearch = evaluate {
    searxng = {
      enable = true;
      uid = 4203;
      package = fixturePackage;
    };
  };
  localSearchService = localSearch.systemd.services.agent-research.serviceConfig;

  localUnitFiles = pkgs.linkFarm "research-local-search-test-units" (
    map
      (name: {
        inherit name;
        path = pkgs.writeText name localSearch.systemd.units.${name}.text;
      })
      [
        "agent-research.service"
        "agent-research.socket"
        "agent-research-searxng.service"
        "agent-research-searxng.socket"
        "agent-research-egress.service"
        "agent-research-egress.socket"
        "agent-research-egress-control.service"
        "agent-research.slice"
        "nftables.service"
      ]
  );
  configurationPath =
    unit:
    lib.removeSuffix ":/etc/research/config.json" (
      builtins.head (
        builtins.filter (value: lib.hasSuffix ":/etc/research/config.json" value) unit.BindReadOnlyPaths
      )
    );
  browserService = granted.systemd.services.agent-research.serviceConfig;
  unitFiles = pkgs.linkFarm "research-module-test-units" (
    map
      (name: {
        inherit name;
        path = pkgs.writeText name granted.systemd.units.${name}.text;
      })
      [
        "agent-research.service"
        "agent-research.socket"
        "agent-research-egress.service"
        "agent-research-egress.socket"
        "agent-research-egress-control.service"
        "agent-research.slice"
        "nftables.service"
      ]
  );
  failures = lib.runTests {
    testResearchJournalNamespace = {
      expr = map (unit: unit.LogNamespace) [
        service
        egress
        control
      ];
      expected = [
        "secure-research"
        "secure-research"
        "secure-research"
      ];
    };
    testReferenceObserverJournalNamespace = {
      expr =
        (evaluate {
          vpnObserver.enable = true;
          vpnObserver.firewallMarker = "/run/research-firewall/ready";
        }).systemd.services.agent-research-vpn-observer.serviceConfig.LogNamespace;
      expected = "secure-research";
    };
    testLocalSearchJournalNamespace = {
      expr = localSearch.systemd.services.agent-research-searxng.serviceConfig.LogNamespace;
      expected = "secure-research";
    };
    testVolatileBoundedJournal = {
      expr = builtins.all (part: lib.hasInfix part journal) [
        "Storage=volatile"
        "RuntimeMaxUse=67108864"
        "RuntimeMaxFileSize=16777216"
        "MaxRetentionSec=7day"
        "RateLimitBurst=100"
        "ForwardToSyslog=no"
      ];
      expected = true;
    };
    testConfigurableJournalBounds = {
      expr =
        builtins.all
          (part: lib.hasInfix part logged.environment.etc."systemd/journald@secure-research.conf".text)
          [
            "RuntimeMaxUse=8388608"
            "RuntimeMaxFileSize=2097152"
            "MaxRetentionSec=3day"
          ];
      expected = true;
    };
    testJournalHasNoPersistentDirectory = {
      expr = valid.systemd.services."systemd-journald@secure-research".serviceConfig.LogsDirectory;
      expected = "";
    };
    testJournalConfigurationRestartsItsInstance = {
      expr = valid.systemd.services."systemd-journald@secure-research".restartTriggers;
      expected = [ valid.environment.etc."systemd/journald@secure-research.conf".source ];
    };
    testTooSmallJournal = {
      expr =
        !(builtins.tryEval
          (evaluate { logging.maxBytes = 4194303; }).services.secureResearch.logging.maxBytes
        ).success;
      expected = true;
    };
    testTooLongJournalRetention = {
      expr =
        !(builtins.tryEval
          (evaluate { logging.retentionDays = 31; }).services.secureResearch.logging.retentionDays
        ).success;
      expected = true;
    };
    testLocalSearchAssertions = {
      expr = builtins.all (item: item.assertion) localSearch.assertions;
      expected = true;
    };
    testLocalSearchNoDirectNetwork = {
      expr = localSearch.systemd.services.agent-research-searxng.serviceConfig.PrivateNetwork;
      expected = true;
    };
    testLocalSearchCredentials = {
      expr = localSearchService.LoadCredential;
      expected = [ ];
    };
    testLocalSearchUidRequired = {
      expr = rejected {
        searxng.enable = true;
        searxng.package = fixturePackage;
      };
      expected = true;
    };
    testLocalSearchUidCannotBeService = {
      expr = rejected {
        searxng = {
          enable = true;
          uid = 4201;
          package = fixturePackage;
        };
      };
      expected = true;
    };
    testNestedWorkerProcCompatibility = {
      expr =
        !service.ProtectKernelTunables
        && egress.ProtectKernelTunables
        && control.ProtectKernelTunables
        && service.CapabilityBoundingSet == ""
        && service.User == "agent-research"
        && service.NoNewPrivileges
        && service.ProtectHostname == "private"
        && service.SystemCallFilter == [ "~sethostname setdomainname" ]
        && service.ProtectProc == "invisible";
      expected = true;
    };
    testDisabledNoUnits = {
      expr = disabled.systemd.services ? agent-research;
      expected = false;
    };
    testDisabledNoUsers = {
      expr = disabled.users.users ? agent-research;
      expected = false;
    };
    testValidAssertions = {
      expr = builtins.all (item: item.assertion) valid.assertions;
      expected = true;
    };
    testMissingIdentity = {
      expr = rejected { serviceUid = null; };
      expected = true;
    };
    testOverlappingIdentities = {
      expr = rejected { egressUid = 4201; };
      expected = true;
    };
    testMissingClients = {
      expr = rejected { clients = { }; };
      expected = true;
    };
    testClientMismatch = {
      expr = rejected { clients.fixture = 4101; };
      expected = true;
    };
    testClientServiceOverlap = {
      expr = rejected { clients.fixture = 4201; };
      expected = true;
    };
    testMissingVpn = {
      expr = rejected { vpnInterface = null; };
      expected = true;
    };
    testMarkedVpnOuterUdp = {
      expr =
        let
          content = marked.networking.nftables.tables.secure_research.content;
        in
        lib.hasInfix "meta mark 21063 ip daddr 192.0.2.2 udp dport 51820 counter accept" content
        && !(lib.hasInfix "meta mark 21063 meta l4proto udp" content);
      expected = true;
    };
    testVpnOuterMarkNeedsEndpoint = {
      expr = rejected { vpnOuterMark = 21063; };
      expected = true;
    };
    testVpnOuterEndpointNeedsMark = {
      expr = rejected { vpnOuterEndpoints = [ outerEndpoint ]; };
      expected = true;
    };
    testMissingResolvers = {
      expr = rejected { resolvers = [ ]; };
      expected = true;
    };
    testTraversalProof = {
      expr = rejected { observationFile = "/run/proof/../state.json"; };
      expected = true;
    };
    testSelfAuthoredProof = {
      expr = rejected { observationFile = "/run/agent-research-egress/control/state.json"; };
      expected = true;
    };
    testDefaultHasNoSearchProvider = {
      expr = valid.services.secureResearch.searchOrder;
      expected = [ ];
    };
    testProviderWithoutGrants = {
      expr = rejected { providers.brave.enable = true; };
      expected = true;
    };
    testStoreCredential = {
      expr = rejected { providers.brave.apiKeyFile = "/nix/store/fixture-secret"; };
      expected = true;
    };
    testSummarizeValid = {
      expr = builtins.all (item: item.assertion) summarized.assertions;
      expected = true;
    };
    testSummarizeCredential = {
      expr = summaryService.LoadCredential;
      expected = [ "provider-openai:/run/secrets/research-fixture-openai" ];
    };
    testSummarizeWithoutModel = {
      expr = rejected {
        searchOrder = [ ];
        providers.openai = openaiProvider // {
          model = null;
        };
        summarizeOrder = [ "openai" ];
      };
      expected = true;
    };
    testSummarizeWithoutContentGrant = {
      expr = rejected {
        searchOrder = [ ];
        providers.openai = openaiProvider // {
          data = [ ];
        };
        summarizeOrder = [ "openai" ];
      };
      expected = true;
    };
    testModelOnlyForSummarization = {
      expr = rejected { providers.brave.model = "gpt-4o-mini"; };
      expected = true;
    };
    testServicePrivateNetwork = {
      expr = service.PrivateNetwork;
      expected = true;
    };
    testControllerPrivateNetwork = {
      expr = control.PrivateNetwork;
      expected = true;
    };
    testEgressHostNetwork = {
      expr = egress.PrivateNetwork or false;
      expected = false;
    };
    testNoCapabilities = {
      expr = map (unit: unit.CapabilityBoundingSet) [
        service
        egress
        control
      ];
      expected = [
        ""
        ""
        ""
      ];
    };
    testPrivateEgressSocket = {
      expr = valid.systemd.sockets.agent-research-egress.socketConfig.SocketGroup;
      expected = "agent-research";
    };
    testClientSocket = {
      expr = valid.systemd.sockets.agent-research.socketConfig.SocketMode;
      expected = "0660";
    };
    testNoGlobalClientGroupGrant = {
      expr = valid.users.groups.agent-research-clients.members;
      expected = [ ];
    };
    testNoAmbientCredentials = {
      expr = service.LoadCredential;
      expected = [ ];
    };
    testGrantedCredentials = {
      expr = browserService.LoadCredential;
      expected = [ "provider-brave:/run/secrets/research-fixture-key" ];
    };
    testEgressNoCredentials = {
      expr = egress.LoadCredential or [ ];
      expected = [ ];
    };
    testControllerNoCredentials = {
      expr = control.LoadCredential or [ ];
      expected = [ ];
    };
    testNoWholeStore = {
      expr = builtins.any (path: path == "/nix/store") (
        service.BindReadOnlyPaths ++ egress.BindReadOnlyPaths
      );
      expected = false;
    };
    testStableLeaseDirectory = {
      expr = control.BindPaths;
      expected = [ "/run/agent-research-egress/control" ];
    };
    testSharedResourceSlice = {
      expr = map (unit: unit.Slice) [
        service
        egress
        control
      ];
      expected = [
        "agent-research.slice"
        "agent-research.slice"
        "agent-research.slice"
      ];
    };
  };
in
assert lib.assertMsg (failures == [ ]) (builtins.toJSON failures);
pkgs.runCommand "research-module-evaluation"
  {
    nativeBuildInputs = [ pkgs.systemd ];
    inherit unitFiles;
    inherit localUnitFiles;
    serviceConfiguration = configurationPath service;
    browserConfiguration = configurationPath browserService;
    summaryConfiguration = configurationPath summaryService;
    localSearchConfiguration = configurationPath localSearchService;
    egressConfiguration = configurationPath egress;
    serviceRoot = service.RootDirectory;
    egressRoot = egress.RootDirectory;
    controlRoot = control.RootDirectory;
  }
  ''
    export SYSTEMD_UNIT_PATH="$unitFiles:${pkgs.systemd}/example/systemd/system"
    export SYSTEMD_COLORS=0
    export XDG_RUNTIME_DIR="$TMPDIR/manager-runtime"
    mkdir -m 700 "$XDG_RUNTIME_DIR"
    systemd-analyze verify --user --man=no \
      "$unitFiles/agent-research.service" "$unitFiles/agent-research.socket" \
      "$unitFiles/agent-research-egress.service" "$unitFiles/agent-research-egress.socket" \
      "$unitFiles/agent-research-egress-control.service" "$unitFiles/agent-research.slice"
    SYSTEMD_UNIT_PATH="$localUnitFiles:${pkgs.systemd}/example/systemd/system" \
      systemd-analyze verify --user --man=no \
        "$localUnitFiles/agent-research.service" \
        "$localUnitFiles/agent-research-searxng.service" "$localUnitFiles/agent-research-searxng.socket"
    mkdir -p "$out"
    cp "$serviceConfiguration" "$out/service.json"
    cp "$browserConfiguration" "$out/browser.json"
    cp "$summaryConfiguration" "$out/summary.json"
    cp "$localSearchConfiguration" "$out/local-search.json"
    cp "$egressConfiguration" "$out/egress.json"
    for root in "$serviceRoot" "$egressRoot" "$controlRoot"; do
      test -d "$root/proc"
      test -d "$root/dev/shm"
      test -f "$root/etc/research/config.json"
      test ! -e "$root/home"
      test ! -e "$root/nix/var/nix/daemon-socket"
    done
  ''
