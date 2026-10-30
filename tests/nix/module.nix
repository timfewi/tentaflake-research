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
    users.groups.fixture-witness-collision.gid = 4101;
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
  exitKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  observerBase = {
    enable = true;
    firewallMarker = "/run/research-firewall/ready";
  };
  observerUnit =
    overrides:
    (evaluate { vpnObserver = observerBase // overrides; })
    .systemd.services.agent-research-vpn-observer.serviceConfig;
  observerService = overrides: (observerUnit overrides).ExecStart;
  defaultObserver = observerService { };
  selectedObserver = observerService {
    linkKind = "wireguard";
    egressPathEvidence = true;
    handshakeWithinSeconds = 180;
    peerPublicKeys = [ exitKey ];
    drainMarker = "/run/research-drain/marker";
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
  markerRejected =
    overrides:
    builtins.any (
      item:
      !item.assertion
      &&
        item.message
        == "The guarded ledger marker must use a normalized, separate persistent directory under /var/lib."
    ) (evaluate overrides).assertions;
  witnessIdentityRejected =
    overrides:
    builtins.any (
      item:
      !item.assertion
      && item.message == "Guarded Research requires an explicit dedicated non-root witness UID/GID."
    ) (evaluate overrides).assertions;
  service = valid.systemd.services.agent-research.serviceConfig;
  guarded = evaluate {
    guardedLedger = {
      enable = true;
      witnessUid = 4203;
    };
  };
  guardedService = guarded.systemd.services.agent-research.serviceConfig;
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
  spiderProvider = {
    enable = true;
    capabilities = [
      "search"
      "scrape"
    ];
    data = [
      "queries"
      "urls"
      "content"
    ];
    apiKeyFile = "/run/secrets/research-fixture-spider";
    requestMicroUsd = 125000;
  };
  spiderConfig = {
    searchOrder = [ "spider" ];
    scrapeOrder = [ "spider" ];
    providers.spider = spiderProvider;
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
  guardedUnitFiles = pkgs.linkFarm "research-guarded-test-units" (
    map
      (name: {
        inherit name;
        path = pkgs.writeText name guarded.systemd.units.${name}.text;
      })
      [
        "agent-research.service"
        "agent-research-ledger-check.service"
        "agent-research-ledger-witness.service"
        "agent-research-ledger-witness.socket"
        "agent-research.socket"
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
  # Decode fixture values only; the derivation below retains the contextual paths.
  configurationValues =
    unit:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext (builtins.readFile (configurationPath unit))
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
    testReferenceObserverSelectsNoExtraEvidenceByDefault = {
      expr = builtins.any (flag: lib.hasInfix flag defaultObserver) [
        "--link-kind"
        "--egress-uid"
        "--dns-resolver"
        "--handshake-within"
        "--peer-public-key"
        "--drain-marker"
      ];
      expected = false;
    };
    testReferenceObserverPassesTheSelectedEvidence = {
      expr = builtins.all (flag: lib.hasInfix flag selectedObserver) [
        "--link-kind wireguard"
        "--egress-uid 4202"
        "--dns-resolver 9.9.9.9"
        "--handshake-within 180"
        "--peer-public-key ${exitKey}"
        "--drain-marker /run/research-drain/marker"
      ];
      expected = true;
    };
    testObserverSelectionsRequireTheObserver = {
      expr = builtins.all rejected [
        { vpnObserver.linkKind = "wireguard"; }
        { vpnObserver.egressPathEvidence = true; }
        { vpnObserver.handshakeWithinSeconds = 180; }
        { vpnObserver.peerPublicKeys = [ exitKey ]; }
        { vpnObserver.drainMarker = "/run/research-drain/marker"; }
      ];
      expected = true;
    };
    testPeerEvidenceRequiresAWireguardLink = {
      expr = builtins.all (selection: rejected { vpnObserver = observerBase // selection; }) [
        { handshakeWithinSeconds = 180; }
        { peerPublicKeys = [ exitKey ]; }
        {
          linkKind = "tun";
          handshakeWithinSeconds = 180;
        }
      ];
      expected = true;
    };
    testPeerEvidenceNeedsExactlyTheNetworkAdministrationCapability = {
      expr = [
        (observerUnit { }).CapabilityBoundingSet
        (observerUnit {
          linkKind = "wireguard";
          handshakeWithinSeconds = 180;
        }).CapabilityBoundingSet
      ];
      expected = [
        ""
        [ "CAP_NET_ADMIN" ]
      ];
    };
    testMoreThanFourPinnedPeersAreRejected = {
      expr = rejected {
        vpnObserver = observerBase // {
          linkKind = "wireguard";
          peerPublicKeys = builtins.genList (_: exitKey) 5;
        };
      };
      expected = true;
    };
    testDrainMarkerMustDifferFromTheFirewallMarker = {
      expr = rejected {
        vpnObserver = {
          enable = true;
          firewallMarker = "/run/research-firewall/ready";
          drainMarker = "/run/research-firewall/ready";
        };
      };
      expected = true;
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
    testGuardedLedgerBlockedAndReadOnlyProjection = {
      expr =
        (builtins.any (
          item:
          !item.assertion
          &&
            item.message
            == "Guarded Research admission is blocked pending continuous host witness review and verification."
        ) guarded.assertions)
        && builtins.elem "/var/lib/agent-research-guard" guardedService.BindReadOnlyPaths
        && !(builtins.elem "/var/lib/agent-research-guard" (guardedService.BindPaths or [ ]));
      expected = true;
    };
    testGuardedLedgerHostPrestartCheck = {
      expr =
        let
          check = guarded.systemd.services.agent-research-ledger-check.serviceConfig;
        in
        check.User == "root"
        && !(check ? RootDirectory)
        && lib.hasInfix "--check-ledger-guard --ledger-marker /var/lib/agent-research-guard/budget.marker" check.ExecStart
        && builtins.elem "agent-research-ledger-check.service" guarded.systemd.services.agent-research.requires
        && builtins.elem "agent-research-ledger-check.service" guarded.systemd.services.agent-research.after;
      expected = true;
    };
    testGuardedLedgerWitnessIsFixedAndSandboxed = {
      expr =
        let
          unit = guarded.systemd.services.agent-research-ledger-witness.serviceConfig;
          socketUnit = guarded.systemd.sockets.agent-research-ledger-witness;
        in
        unit.User == "agent-research-ledger-witness"
        && unit.Group == "agent-research-ledger-witness"
        && guarded.users.users.agent-research-ledger-witness.uid == 4203
        && guarded.users.groups.agent-research-ledger-witness.gid == 4203
        && !(unit.PrivateNetwork or false)
        && !(unit ? RootDirectory)
        && !(unit ? BindReadOnlyPaths)
        && !(unit ? ProtectSystem)
        && !(unit.PrivateTmp or false)
        && unit.NoNewPrivileges
        && unit.RestrictNamespaces
        && unit.RestrictAddressFamilies == [ "AF_UNIX" ]
        && unit.CapabilityBoundingSet == ""
        && unit.Restart == "no"
        && lib.hasInfix "--ledger-marker /var/lib/agent-research-guard/budget.marker --witness-state-directory /var/lib/agent-research --witness-service-uid 4201 --witness-process-uid 4203" unit.ExecStart
        && socketUnit.listenStreams == [ "/run/agent-research-ledger-witness/socket" ]
        && socketUnit.socketConfig.SocketUser == "root"
        && socketUnit.socketConfig.SocketGroup == "agent-research"
        && socketUnit.socketConfig.SocketMode == "0660"
        && builtins.elem "/run/agent-research-ledger-witness/socket" guardedService.BindReadOnlyPaths
        && !(builtins.elem "/run/agent-research-ledger-witness" guardedService.BindReadOnlyPaths)
        && builtins.elem "agent-research-ledger-witness.service" guarded.systemd.services.agent-research.bindsTo
        && builtins.elem "agent-research-ledger-witness.socket" guarded.systemd.services.agent-research-ledger-witness.bindsTo;
      expected = true;
    };
    testGuardedWitnessSocketIsPassedToService = {
      expr = (configurationValues guardedService).ledger_guard_witness_socket;
      expected = "/run/agent-research-ledger-witness/socket";
    };
    testGuardedWitnessRequiresExplicitDistinctUid = {
      expr =
        witnessIdentityRejected { guardedLedger.enable = true; }
        && witnessIdentityRejected {
          guardedLedger = {
            enable = true;
            witnessUid = 4201;
          };
        }
        && witnessIdentityRejected {
          guardedLedger = {
            enable = true;
            witnessUid = 4202;
          };
        }
        && witnessIdentityRejected {
          guardedLedger = {
            enable = true;
            witnessUid = 4100;
          };
        };
      expected = true;
    };
    testGuardedWitnessRejectsConfiguredUserAndGroupCollisions = {
      expr =
        builtins.any
          (
            item:
            !item.assertion && item.message == "Research service UID collides with another configured user."
          )
          (evaluate {
            guardedLedger = {
              enable = true;
              witnessUid = 4100;
            };
          }).assertions
        &&
          builtins.any
            (
              item:
              !item.assertion && item.message == "Research service GID collides with another configured group."
            )
            (evaluate {
              guardedLedger = {
                enable = true;
                witnessUid = 4101;
              };
            }).assertions;
      expected = true;
    };
    testGuardedLedgerIsOptIn = {
      expr =
        !valid.services.secureResearch.guardedLedger.enable
        && !(builtins.elem "/var/lib/agent-research-guard" service.BindReadOnlyPaths);
      expected = true;
    };
    testGuardedLedgerIsPassedToService = {
      expr = (configurationValues guardedService).ledger_guard_marker;
      expected = "/var/lib/agent-research-guard/budget.marker";
    };
    testDefaultLedgerIsUnguardedInService = {
      expr = (configurationValues service).ledger_guard_marker;
      expected = null;
    };
    testConfigurationPathsKeepDependencies = {
      expr = builtins.all (unit: builtins.getContext (configurationPath unit) != { }) [
        service
        guardedService
      ];
      expected = true;
    };
    testGuardedLedgerMarkerOutsideState = {
      expr = markerRejected {
        guardedLedger = {
          enable = true;
          markerPath = "/var/lib/agent-research/budget.marker";
        };
      };
      expected = true;
    };
    testGuardedLedgerMarkerMustBePersistentAndNormalized = {
      expr =
        markerRejected {
          guardedLedger = {
            enable = true;
            markerPath = "/run/agent-research-guard/budget.marker";
          };
        }
        && markerRejected {
          guardedLedger = {
            enable = true;
            markerPath = "/var/lib/agent-research-guard/../budget.marker";
          };
        };
      expected = true;
    };
    testGuardedMarkerCannotReplaceLock = {
      expr = markerRejected {
        guardedLedger = {
          enable = true;
          markerPath = "/var/lib/agent-research-guard/ledger.lock";
        };
      };
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
    testSpiderDualGrant = {
      expr = rejected spiderConfig;
      expected = false;
    };
    testSpiderSearchOnly = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            capabilities = [ "search" ];
            data = [ "queries" ];
          };
        }
      );
      expected = false;
    };
    testSpiderScrapeOnly = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            capabilities = [ "scrape" ];
            data = [
              "urls"
              "content"
            ];
          };
        }
      );
      expected = false;
    };
    testSpiderMissingQueries = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            data = [
              "urls"
              "content"
            ];
          };
        }
      );
      expected = true;
    };
    testSpiderMissingUrls = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            data = [
              "queries"
              "content"
            ];
          };
        }
      );
      expected = true;
    };
    testSpiderMissingContent = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            data = [
              "queries"
              "urls"
            ];
          };
        }
      );
      expected = true;
    };
    testSpiderZeroPrice = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            requestMicroUsd = 0;
          };
        }
      );
      expected = true;
    };
    testDisabledSpiderZeroPriceUnchanged = {
      expr = rejected (
        spiderConfig
        // {
          providers.spider = spiderProvider // {
            enable = false;
            requestMicroUsd = 0;
          };
        }
      );
      expected = false;
    };
    testBraveZeroPriceUnchanged = {
      expr = rejected {
        searchOrder = [ "brave" ];
        providers.brave = {
          enable = true;
          capabilities = [ "search" ];
          data = [ "queries" ];
          apiKeyFile = "/run/secrets/research-fixture-brave";
          requestMicroUsd = 0;
        };
      };
      expected = false;
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
    inherit guardedUnitFiles;
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
    SYSTEMD_UNIT_PATH="$guardedUnitFiles:${pkgs.systemd}/example/systemd/system" \
      systemd-analyze verify --user --man=no \
        "$guardedUnitFiles/agent-research.service" "$guardedUnitFiles/agent-research-ledger-check.service" \
        "$guardedUnitFiles/agent-research-ledger-witness.socket" "$guardedUnitFiles/agent-research-ledger-witness.service"
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
