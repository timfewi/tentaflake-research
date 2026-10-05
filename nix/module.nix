{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption mkEnableOption types;
  cfg = config.services.secureResearch;
  uidType = types.ints.between 1 4294967294;
  runtimePath = types.strMatching "/[a-zA-Z0-9_./-]+";
  serviceUid = if cfg.serviceUid == null then 1 else cfg.serviceUid;
  egressUid = if cfg.egressUid == null then 2 else cfg.egressUid;
  interface = if cfg.vpnInterface == null then "unconfigured0" else cfg.vpnInterface;
  observationDirectory = builtins.dirOf cfg.observationFile;
  socket = "/run/agent-research/socket";
  egressSocket = "/run/agent-research-egress/socket";
  controlDirectory = "/run/agent-research-egress/control";
  controlFile = "${controlDirectory}/state.json";
  journalNamespace = "secure-research";
  fonts = pkgs.makeFontsConf {
    fontDirectories = [
      pkgs.dejavu_fonts
      pkgs.noto-fonts-color-emoji
    ];
    impureFontDirectories = [ ];
    includes = [ ];
  };
  # Enabled-module evaluation realizes these exact runtime closures (IFD).
  # Never replace them with a projection of the entire store.
  closurePaths =
    roots:
    lib.splitString "\n" (
      lib.removeSuffix "\n" (builtins.readFile "${pkgs.closureInfo { rootPaths = roots; }}/store-paths")
    );
  ocrLanguages = lib.filter (language: language != "") (lib.splitString "+" cfg.ocr.languages);
  # Bounded local OCR runs inside the isolated parser worker. Only the selected
  # Tesseract language data enters the read-only parser closure.
  ocrTesseract = pkgs.tesseract.override { enableLanguages = ocrLanguages; };
  parserPaths = closurePaths (
    [
      cfg.package
      pkgs.poppler-utils
    ]
    ++ lib.optional cfg.ocr.enable ocrTesseract
  );
  browserPaths =
    if cfg.browser.enable then
      closurePaths [
        cfg.package
        cfg.browser.package
        cfg.browser.package.sandbox
        fonts
      ]
    else
      [ ];
  servicePaths = lib.unique (parserPaths ++ browserPaths ++ closurePaths [ pkgs.bubblewrap ]);
  egressPaths = closurePaths [ cfg.egressPackage ];
  serviceConfig = pkgs.writeText "research-config.json" (
    builtins.toJSON {
      version = 1;
      socket_path = socket;
      state_directory = "/var/lib/agent-research";
      egress_socket = egressSocket;
      # SO_PEERCRED reports the root socket creator across systemd activation,
      # not the unprivileged process accepting the inherited descriptor.
      egress_uid = 0;
      egress_control_file = controlFile;
      allowed_client_uids = builtins.attrValues cfg.clients;
      inherit (cfg) privacy;
      providers = lib.mapAttrs (name: provider: {
        inherit (provider) enable capabilities data;
        credential = if provider.apiKeyFile == null then null else "provider-${name}";
        storage_rights = provider.storageRights;
        request_micro_usd = provider.requestMicroUsd;
        inherit (provider) model endpoint;
      }) cfg.providers;
      search_order = cfg.searchOrder;
      scrape_order = cfg.scrapeOrder;
      summarize_order = cfg.summarizeOrder;
      searxng_socket = if cfg.searxng.enable then "/run/agent-research-searxng/socket" else null;
      inherit (cfg) limits retention robots;
      workers = {
        executable = "${cfg.package}/bin/research-worker";
        bubblewrap = "${pkgs.bubblewrap}/bin/bwrap";
        pdfinfo = "${pkgs.poppler-utils}/bin/pdfinfo";
        pdftotext = "${pkgs.poppler-utils}/bin/pdftotext";
        pdftoppm = "${pkgs.poppler-utils}/bin/pdftoppm";
        # Only pull the recognizer into the closure when OCR is enabled; a
        # disabled deployment keeps the previous parser closure.
        tesseract = if cfg.ocr.enable then "${ocrTesseract}/bin/tesseract" else "/unconfigured/tesseract";
        ocr = {
          enabled = cfg.ocr.enable;
          inherit (cfg.ocr)
            languages
            pages
            dpi
            seconds
            bytes
            ;
        };
        store_paths = parserPaths;
      };
      browser = {
        inherit (cfg.browser) enable;
        idle_seconds = cfg.browser.idleSeconds;
        inherit (cfg.browser) width height;
        read_post_rules = cfg.browser.readPostRules;
        profile = cfg.browser.profile;
      }
      // lib.optionalAttrs cfg.browser.enable {
        executable = "${cfg.browser.package}/bin/chromium";
        sandbox = {
          worker = "${cfg.package}/bin/research-browser-worker";
          bubblewrap = "${pkgs.bubblewrap}/bin/bwrap";
          chromium_sandbox = "${cfg.browser.package.sandbox}/bin/__chromium-suid-sandbox";
          fontconfig = toString fonts;
          store_paths = browserPaths;
        };
      };
    }
  );
  egressConfig = pkgs.writeText "research-egress-config.json" (
    builtins.toJSON {
      socket_path = egressSocket;
      control_file = controlFile;
      allowed_peer_uids = [ serviceUid ] ++ lib.optional cfg.searxng.enable cfg.searxng.uid;
      vpn_interface = interface;
      inherit (cfg) resolvers;
      denied_networks = cfg.extraDeniedNetworks;
      max_connections = 64;
      connection_seconds = 60;
      connection_bytes = 134217728;
    }
  );
  # Immutable empty mount targets. Runtime contents are bind-mounted individually;
  # this layout neither copies the closure nor exposes unrelated store paths.
  root =
    name: paths:
    pkgs.runCommand "research-${name}-root" { } ''
      mkdir -p "$out"/{dev/shm,proc,sys,tmp,var/tmp,var/lib/agent-research,etc/research,nix/store}
      mkdir -p "$out/run/agent-research" "$out/run/agent-research-searxng" "$out${controlDirectory}" \
        "$out/run/credentials/agent-research.service" "$out${observationDirectory}"
      touch "$out/etc/research/config.json"
      for path in ${lib.escapeShellArgs paths}; do
        if test -d "$path"; then
          mkdir -p "$out$path"
        else
          mkdir -p "$(dirname "$out$path")"
          touch "$out$path"
        fi
      done
    '';
  common = {
    LogNamespace = journalNamespace;
    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    PrivateDevices = true;
    PrivateUsers = false; # Unix peer UIDs must retain host identity.
    ProtectSystem = "strict";
    ProtectHome = true;
    MountAPIVFS = true;
    ProtectProc = "invisible";
    ProtectControlGroups = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    SystemCallArchitectures = "native";
    Restart = "on-failure";
    RestartSec = 2;
  };
  providerType = types.submodule {
    options = {
      enable = mkEnableOption "this explicitly granted provider";
      capabilities = mkOption {
        type = types.listOf (
          types.enum [
            "search"
            "scrape"
            "summarize"
          ]
        );
        default = [ ];
      };
      data = mkOption {
        type = types.listOf (
          types.enum [
            "queries"
            "urls"
            "content"
          ]
        );
        default = [ ];
      };
      apiKeyFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Runtime credential path, never secret contents or a Nix store file.";
      };
      storageRights = mkOption {
        type = types.bool;
        default = false;
      };
      requestMicroUsd = mkOption {
        type = types.nullOr (types.ints.between 0 1000000000);
        default = null;
        description = "Fixed per-request price, or for summarization the per-request ceiling settled on success.";
      };
      model = mkOption {
        type = types.nullOr (types.strMatching "[A-Za-z0-9_.:/-]{1,128}");
        default = null;
        description = "Operator-selected model for a summarization provider.";
      };
      endpoint = mkOption {
        type = types.nullOr (types.strMatching "https://[A-Za-z0-9.-]+");
        default = null;
        description = "Bare public HTTPS origin of a self-hosted adapter (SearXNG only). The Rust service re-validates it as a public origin and the egress proxy still enforces public-address policy per request.";
      };
    };
  };
in
{
  imports = [
    ./searxng.nix
    ./container-clients.nix
  ];
  options.services.secureResearch = {
    enable = mkEnableOption "the isolated public research service (deployment acceptance still required)";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.research-service;
    };
    egressPackage = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.research-egress;
    };
    serviceUid = mkOption {
      type = types.nullOr uidType;
      default = null;
    };
    egressUid = mkOption {
      type = types.nullOr uidType;
      default = null;
    };
    clients = mkOption {
      type = types.attrsOf uidType;
      default = { };
      description = "Peer-UID allowlist: local usernames mapped to explicit host UIDs. Grant socketGroup separately to authorized client sessions; this does not grant global group membership.";
    };
    socketGroup = mkOption {
      type = types.strMatching "[a-z_][a-z0-9_-]*";
      default = "agent-research-clients";
    };
    vpnInterface = mkOption {
      type = types.nullOr (types.strMatching "[a-zA-Z0-9_.-]{1,15}");
      default = null;
    };
    vpnOuterMark = mkOption {
      type = types.nullOr (types.ints.between 1 4294967295);
      default = null;
      description = "Optional mark reserved for encrypted outer UDP packets from the trusted VPN. The VPN must set it; research identities must not be able to set socket marks. Requires vpnOuterEndpoints.";
    };
    vpnOuterEndpoints = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            address = mkOption {
              type = types.strMatching "[0-9a-fA-F:.]{2,45}";
              description = "Literal IPv4 or IPv6 address of a trusted VPN peer.";
            };
            port = mkOption {
              type = types.port;
              description = "UDP port of that peer.";
            };
          };
        }
      );
      default = [ ];
      description = "VPN peer endpoints that marked outer UDP packets may reach outside the tunnel interface. Required with, and only valid with, vpnOuterMark; a marked packet to any other destination stays denied.";
    };
    resolvers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "One to four public DNS IP literals, carried over the VPN path.";
    };
    extraDeniedNetworks = mkOption {
      type = types.listOf types.str;
      default = [ ];
    };
    observationFile = mkOption {
      type = runtimePath;
      default = "/run/research-vpn/observation.json";
      description = "Lease in a dedicated root-controlled adapter directory; the module does not fabricate VPN readiness.";
    };
    drainSeconds = mkOption {
      type = types.ints.between 1 300;
      default = 60;
    };
    logging = {
      maxBytes = mkOption {
        type = types.ints.between 4194304 1073741824;
        default = 67108864;
        description = "Maximum target size in bytes for the volatile Research journal namespace; journald may temporarily exceed this while its active file is open.";
      };
      retentionDays = mkOption {
        type = types.ints.between 1 30;
        default = 7;
        description = "Maximum target retention for rotated Research journal files, in days.";
      };
    };
    vpnObserver = {
      enable = mkEnableOption "the reference VPN/firewall observation producer (disabled by default; the operator may supply their own adapter)";
      region = mkOption {
        type = types.nullOr (types.strMatching "[A-Z]{2}");
        default = null;
        description = "Operator-declared ISO 3166-1 alpha-2 exit region published with the observation. It is never inferred from the tunnel.";
      };
      firewallMarker = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Root-owned, non-group/world-writable marker created by the operator's firewall installer. It is a marker, not proof of the firewall rules.";
      };
      refreshSeconds = mkOption {
        type = types.ints.between 1 5;
        default = 5;
        description = "Observation renewal interval; the independent lease lifetime is ten seconds, leaving at least five seconds of renewal headroom.";
      };
      linkKind = mkOption {
        type = types.nullOr (
          types.enum [
            "wireguard"
            "tun"
          ]
        );
        default = null;
        description = "Require the VPN interface to be this kind of link (a WireGuard device or a layer-3 tun device such as Tailscale's). Not selected by default; no VPN vendor is required.";
      };
      egressPathEvidence = mkEnableOption "observation of the egress identity's paths: unmarked IPv4 traffic must use the tunnel, IPv6 must not leave through another interface and every configured resolver must be reached through the tunnel. Not selected by default; the baseline only needs a default route on the interface";
      drainMarker = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "A root-owned, non-group/world-writable marker whose presence requests a planned exit change: the observer reports draining for the current generation and a new generation once the marker is removed. Its parent directories must be root-owned and not writable by other identities; an untrustworthy marker makes the exit offline.";
      };
    };
    privacy = mkOption {
      type = types.enum [
        "practical"
        "strict"
      ];
      default = "practical";
    };
    providers = mkOption {
      type = types.attrsOf providerType;
      default = { };
    };
    searchOrder = mkOption {
      type = types.listOf (
        types.enum [
          "brave"
          "tavily"
          "searxng"
        ]
      );
      default = if cfg.searxng.enable then [ "searxng" ] else [ ];
      description = "Explicit search adapter preference; empty disables search. Enabling the local SearXNG service selects its adapter by default.";
    };
    scrapeOrder = mkOption {
      type = types.listOf (
        types.enum [
          "spider"
          "firecrawl"
        ]
      );
      default = [ ];
    };
    summarizeOrder = mkOption {
      type = types.listOf (types.enum [ "openai" ]);
      default = [ ];
      description = "Separately enabled LLM summarization (OpenAI-compatible chat completions). Empty keeps Research fully usable without any LLM.";
    };
    limits = mkOption {
      type = types.attrsOf types.ints.unsigned;
      default = { };
      description = "Rust Limits fields; omitted fields use validated application defaults.";
    };
    retention = mkOption {
      type = types.attrsOf types.ints.unsigned;
      default = { };
    };
    robots = mkOption {
      inherit (pkgs.formats.json { }) type;
      default = { };
    };
    ocr = {
      enable = mkEnableOption "bounded local OCR for textless PDFs (offline, inside the isolated parser worker; no network or LLM)";
      languages = mkOption {
        type = types.strMatching "[a-zA-Z0-9_+]+";
        default = "eng";
        description = "Tesseract language codes joined by '+', for example \"eng\" or \"eng+deu\". The selected traineddata is added to the read-only parser closure.";
      };
      pages = mkOption {
        type = types.ints.between 1 200;
        default = 32;
        description = "Maximum PDF pages to recognize; never more than the document's page count.";
      };
      dpi = mkOption {
        type = types.ints.between 100 400;
        default = 200;
        description = "Rasterization resolution for the OCR phase.";
      };
      seconds = mkOption {
        type = types.ints.between 1 120;
        default = 10;
        description = "Per-command timeout for the rasterizer and each page recognizer.";
      };
      bytes = mkOption {
        type = types.ints.between 65536 67108864;
        default = 4194304;
        description = "Total recognized text bytes accepted across all OCR pages.";
      };
    };
    browser = {
      enable = mkEnableOption "isolated Chromium reading";
      package = mkOption {
        type = types.package;
        default = pkgs.chromium;
      };
      width = mkOption {
        type = types.ints.between 640 2560;
        default = 1365;
      };
      height = mkOption {
        type = types.ints.between 480 1440;
        default = 768;
      };
      idleSeconds = mkOption {
        type = types.ints.between 1 300;
        default = 60;
      };
      readPostRules = mkOption {
        type = types.listOf (pkgs.formats.json { }).type;
        default = [ ];
      };
      profile = mkOption {
        type = types.enum [
          "neutral"
          "exit_region"
        ];
        default = "neutral";
        description = "Browser profile policy: a fixed coherent neutral profile, or a coherent profile derived from the observed VPN exit region. Rotation happens only between sessions; no anonymity is promised.";
      };
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      (import ./network-boundary.nix {
        inherit lib serviceUid egressUid;
        vpnInterface = interface;
        inherit (cfg) vpnOuterMark;
        vpnOuterEndpoints = map (endpoint: { inherit (endpoint) address port; }) cfg.vpnOuterEndpoints;
      })
      (import ./resource-boundary.nix { inherit lib serviceUid; })
      (lib.mkIf cfg.searxng.enable {
        systemd.services.agent-research-searxng.serviceConfig.LogNamespace = journalNamespace;
      })
      {
        assertions = [
          {
            assertion = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
            message = "Research deployment is currently supported only on x86_64-linux.";
          }
          {
            assertion = (cfg.vpnOuterMark == null) == (cfg.vpnOuterEndpoints == [ ]);
            message = "Research vpnOuterMark and vpnOuterEndpoints must be configured together.";
          }
          {
            assertion = cfg.serviceUid != null && cfg.egressUid != null && serviceUid != egressUid;
            message = "Research requires explicit distinct service/egress UIDs.";
          }
          {
            assertion =
              cfg.clients != { }
              && builtins.all (uid: uid != serviceUid && uid != egressUid) (builtins.attrValues cfg.clients);
            message = "Research requires clients distinct from its service identities.";
          }
          {
            assertion = builtins.all (name: (config.users.users.${name}.uid or null) == cfg.clients.${name}) (
              builtins.attrNames cfg.clients
            );
            message = "Research clients must match explicitly configured local user UIDs.";
          }
          {
            assertion =
              cfg.vpnInterface != null
              && builtins.length cfg.resolvers >= 1
              && builtins.length cfg.resolvers <= 4;
            message = "Research requires an explicit VPN interface and public resolvers.";
          }
          {
            assertion =
              lib.hasPrefix "/run/" cfg.observationFile
              && observationDirectory != "/run"
              && builtins.all (
                part:
                !(builtins.elem part [
                  ""
                  "."
                  ".."
                ])
              ) (builtins.tail (lib.splitString "/" cfg.observationFile))
              && !(lib.hasPrefix "/run/agent-research" cfg.observationFile);
            message = "VPN proof must use a separate dedicated normalized /run directory.";
          }
          {
            assertion = !cfg.vpnObserver.enable || cfg.vpnObserver.firewallMarker != null;
            message = "The reference VPN observer requires vpnObserver.firewallMarker.";
          }
          {
            assertion =
              cfg.vpnObserver.enable
              || (
                cfg.vpnObserver.linkKind == null
                && !cfg.vpnObserver.egressPathEvidence
                && cfg.vpnObserver.drainMarker == null
              );
            message = "vpnObserver.linkKind, egressPathEvidence and drainMarker apply only with vpnObserver.enable.";
          }
          {
            assertion =
              cfg.vpnObserver.drainMarker == null
              || cfg.vpnObserver.drainMarker != cfg.vpnObserver.firewallMarker;
            message = "vpnObserver.drainMarker must differ from vpnObserver.firewallMarker.";
          }
          {
            assertion =
              !(builtins.elem cfg.socketGroup [
                "agent-research"
                "agent-research-egress"
              ]);
            message = "Research client group must differ from service groups.";
          }
          {
            assertion = builtins.all (
              name:
              builtins.elem name [
                "brave"
                "tavily"
                "searxng"
                "spider"
                "firecrawl"
                "openai"
              ]
            ) (builtins.attrNames cfg.providers);
            message = "Only Brave/Tavily/SearXNG (search), Spider/Firecrawl (scrape) and OpenAI (summarize) are currently implemented; new providers need their own adapter and grants.";
          }
        ]
        ++ lib.mapAttrsToList (name: provider: {
          assertion =
            (
              !provider.enable
              || (
                (
                  if name == "searxng" then
                    provider.apiKeyFile == null
                    && provider.requestMicroUsd == null
                    && (if cfg.searxng.enable then provider.endpoint == null else provider.endpoint != null)
                  else
                    provider.apiKeyFile != null && provider.requestMicroUsd != null && provider.endpoint == null
                )
                && (
                  if
                    builtins.elem name [
                      "brave"
                      "tavily"
                      "searxng"
                    ]
                  then
                    builtins.elem "search" provider.capabilities && builtins.elem "queries" provider.data
                  else if name == "openai" then
                    builtins.elem "summarize" provider.capabilities
                    && builtins.elem "content" provider.data
                    && provider.model != null
                  else
                    builtins.elem "scrape" provider.capabilities
                    && builtins.elem "urls" provider.data
                    && builtins.elem "content" provider.data
                )
              )
            )
            && (provider.model == null || name == "openai")
            && (provider.apiKeyFile == null || !(lib.hasPrefix "/nix/store/" provider.apiKeyFile));
          message = "Provider ${name} requires explicit capability/data grants and, except for credential-less SearXNG, a runtime-only credential, a price and, where applicable, a model; a fixed-endpoint adapter must not set endpoint and SearXNG must set it.";
        }) cfg.providers
        ++ lib.mapAttrsToList (name: user: {
          assertion =
            builtins.elem name [
              "agent-research"
              "agent-research-egress"
            ]
            || !(builtins.elem user.uid [
              serviceUid
              egressUid
            ]);
          message = "Research service UID collides with another configured user.";
        }) config.users.users
        ++ lib.mapAttrsToList (name: group: {
          assertion =
            builtins.elem name [
              "agent-research"
              "agent-research-egress"
            ]
            || !(builtins.elem group.gid [
              serviceUid
              egressUid
            ]);
          message = "Research service GID collides with another configured group.";
        }) config.users.groups;

        users.groups = {
          agent-research.gid = serviceUid;
          agent-research-egress.gid = egressUid;
          ${cfg.socketGroup} = { };
        };
        users.users = {
          agent-research = {
            uid = serviceUid;
            group = "agent-research";
            isSystemUser = true;
          };
          agent-research-egress = {
            uid = egressUid;
            group = "agent-research-egress";
            isSystemUser = true;
          };
        };
        systemd.tmpfiles.rules = [
          "d /run/agent-research 0755 root root -"
          "d /run/agent-research-egress 0755 root root -"
          "d ${controlDirectory} 0755 root root -"
        ];
        environment.etc."systemd/journald@${journalNamespace}.conf".text = ''
          [Journal]
          Storage=volatile
          RuntimeMaxUse=${toString cfg.logging.maxBytes}
          RuntimeMaxFileSize=${toString (builtins.div cfg.logging.maxBytes 4)}
          MaxRetentionSec=${toString cfg.logging.retentionDays}day
          MaxFileSec=1day
          RateLimitIntervalSec=30s
          RateLimitBurst=100
          ForwardToSyslog=no
          ForwardToKMsg=no
          ForwardToConsole=no
          ForwardToWall=no
        '';
        systemd.sockets = {
          agent-research = {
            wantedBy = [ "sockets.target" ];
            listenStreams = [ socket ];
            socketConfig = {
              SocketUser = "root";
              SocketGroup = cfg.socketGroup;
              SocketMode = "0660";
              DirectoryMode = "0755";
              RemoveOnStop = true;
            };
          };
          agent-research-egress = {
            wantedBy = [ "sockets.target" ];
            listenStreams = [ egressSocket ];
            socketConfig = {
              SocketUser = "root";
              SocketGroup = "agent-research";
              SocketMode = "0660";
              DirectoryMode = "0755";
              RemoveOnStop = true;
            };
          };
        };
        systemd.services = {
          "systemd-journald@${journalNamespace}" = {
            overrideStrategy = "asDropin";
            restartTriggers = [ config.environment.etc."systemd/journald@${journalNamespace}.conf".source ];
            stopIfChanged = false;
            # The upstream template creates a persistent directory even with
            # Storage=volatile unless this directive is cleared for our instance.
            serviceConfig.LogsDirectory = "";
          };
          agent-research = {
            requires = [
              "agent-research-egress.socket"
              "agent-research-egress-control.service"
            ]
            ++ lib.optional cfg.searxng.enable "agent-research-searxng.socket";
            after = [
              "agent-research-egress.socket"
              "agent-research-egress-control.service"
            ]
            ++ lib.optional cfg.searxng.enable "agent-research-searxng.socket";
            serviceConfig = common // {
              User = "agent-research";
              Group = "agent-research";
              ExecStart = "${cfg.package}/bin/research-service --listen-fd 3 --temporary-directory /tmp/research --public-only --config /etc/research/config.json";
              RootDirectory = root "service" servicePaths;
              BindReadOnlyPaths =
                servicePaths
                ++ [
                  "${serviceConfig}:/etc/research/config.json"
                  "/run/agent-research"
                  "/run/agent-research-egress"
                ]
                ++ lib.optional cfg.searxng.enable "/run/agent-research-searxng";
              StateDirectory = "agent-research";
              StateDirectoryMode = "0700";
              PrivateNetwork = true;
              # Its /proc submounts prevent unprivileged workers from mounting
              # their own PID namespace's procfs ("Mount too revealing").
              # Keep this exception local to the supervisor: root-owned sysctls
              # remain unwritable to its nonroot UID with an empty capability
              # set. Workers retain independent user/PID/network namespaces.
              ProtectKernelTunables = false;
              # Retain the private UTS namespace and syscall denial without
              # ProtectHostname=yes's locked hostname/domainname proc mounts.
              ProtectHostname = "private";
              SystemCallFilter = [ "~sethostname setdomainname" ];
              SystemCallErrorNumber = "EPERM";
              RestrictAddressFamilies = [
                "AF_UNIX"
                "AF_INET"
                "AF_INET6"
                "AF_NETLINK"
              ];
              LoadCredential = lib.mapAttrsToList (name: provider: "provider-${name}:${provider.apiKeyFile}") (
                lib.filterAttrs (_: provider: provider.enable && provider.apiKeyFile != null) cfg.providers
              );
            };
          };
          agent-research-egress = {
            requires = [ "agent-research-egress-control.service" ];
            after = [ "agent-research-egress-control.service" ];
            bindsTo = [ "agent-research-egress-control.service" ];
            serviceConfig = common // {
              User = "agent-research-egress";
              Group = "agent-research-egress";
              ExecStart = "${cfg.egressPackage}/bin/research-egress --listen-fd 3 --config /etc/research/config.json";
              RootDirectory = root "egress" egressPaths;
              BindReadOnlyPaths = egressPaths ++ [
                "${egressConfig}:/etc/research/config.json"
                "/run/agent-research-egress"
              ];
              RestrictNamespaces = true;
              RestrictAddressFamilies = [
                "AF_UNIX"
                "AF_INET"
                "AF_INET6"
                "AF_NETLINK"
              ];
            };
          };
          agent-research-egress-control = {
            wantedBy = [ "multi-user.target" ];
            requires = [ "nftables.service" ];
            after = [
              "nftables.service"
              "systemd-tmpfiles-setup.service"
            ];
            bindsTo = [ "nftables.service" ];
            serviceConfig = common // {
              User = "root";
              Group = "root";
              ExecStart = "${cfg.egressPackage}/bin/research-egress-control --input ${cfg.observationFile} --output ${controlFile} --drain-seconds ${toString cfg.drainSeconds}";
              RootDirectory = root "control" egressPaths;
              BindReadOnlyPaths = egressPaths ++ [ observationDirectory ];
              BindPaths = [ controlDirectory ];
              ReadWritePaths = [ controlDirectory ];
              PrivateNetwork = true;
              RestrictNamespaces = true;
              RestrictAddressFamilies = [ "AF_UNIX" ];
            };
          };
        };
      }
      (lib.mkIf cfg.vpnObserver.enable {
        systemd.tmpfiles.rules = [ "d ${observationDirectory} 0755 root root -" ];
        systemd.services.agent-research-vpn-observer = {
          wantedBy = [ "multi-user.target" ];
          after = [ "systemd-tmpfiles-setup.service" ];
          serviceConfig = common // {
            User = "root";
            Group = "root";
            ExecStart =
              "${cfg.egressPackage}/bin/research-vpn-observer --interface ${interface} --output ${cfg.observationFile} --refresh-seconds ${toString cfg.vpnObserver.refreshSeconds} --firewall-marker ${cfg.vpnObserver.firewallMarker}"
              + lib.optionalString (cfg.vpnObserver.region != null) " --region ${cfg.vpnObserver.region}"
              + lib.optionalString (cfg.vpnObserver.linkKind != null) " --link-kind ${cfg.vpnObserver.linkKind}"
              + lib.optionalString cfg.vpnObserver.egressPathEvidence (
                " --egress-uid ${toString egressUid}"
                + lib.concatMapStrings (resolver: " --dns-resolver ${resolver}") cfg.resolvers
              )
              + lib.optionalString (
                cfg.vpnObserver.drainMarker != null
              ) " --drain-marker ${cfg.vpnObserver.drainMarker}";
            # No RootDirectory: the observer must read the host's /sys/class/net
            # and query its routing tables over NETLINK_ROUTE, which a private
            # network namespace would hide.
            ReadWritePaths = [ observationDirectory ];
            RestrictNamespaces = true;
            RestrictAddressFamilies = [
              "AF_UNIX"
              "AF_NETLINK"
            ];
          };
        };
      })
    ]
  );
}
