{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.secureResearch;
  local = cfg.searxng;
  uid = if local.uid == null then 3 else local.uid;
  socketDirectory = "/run/agent-research-searxng";
  python = pkgs.python3.withPackages (packages: [
    local.package
    packages.gunicorn
  ]);
  runner = pkgs.writeShellScript "research-searxng-wsgi" ''
    exec ${python}/bin/gunicorn --bind 127.0.0.1:8888 --workers 1 --threads 8 \
      --worker-class gthread --timeout 30 searx.webapp:app
  '';
  paths = lib.splitString "\n" (
    lib.removeSuffix "\n" (
      builtins.readFile "${
        pkgs.closureInfo {
          rootPaths = [
            cfg.package
            runner
            pkgs.cacert
          ];
        }
      }/store-paths"
    )
  );
  root = pkgs.runCommand "research-searxng-root" { } ''
    mkdir -p "$out"/{dev,proc,sys,tmp,etc/ssl/certs,nix/store,run/agent-research-egress,run/agent-research-searxng}
    touch "$out/etc/ssl/certs/ca-certificates.crt"
    for path in ${lib.escapeShellArgs paths}; do
      if test -d "$path"; then mkdir -p "$out$path"; else
        mkdir -p "$(dirname "$out$path")"
        touch "$out$path"
      fi
    done
  '';
in
{
  options.services.secureResearch.searxng = {
    enable = lib.mkEnableOption "local SearXNG over a private Unix socket and mandatory Research egress";
    uid = lib.mkOption {
      type = lib.types.nullOr (lib.types.ints.between 1 4294967294);
      default = null;
      description = "Distinct fixed identity for the isolated local SearXNG service.";
    };
    package = lib.mkPackageOption pkgs "searxng" { };
  };
  config = lib.mkIf (cfg.enable && local.enable) {
    assertions = [
      {
        assertion =
          local.uid != null
          && !(builtins.elem uid (
            [
              cfg.serviceUid
              cfg.egressUid
            ]
            ++ builtins.attrValues cfg.clients
          ));
        message = "Local SearXNG needs its own explicit UID, distinct from Research and clients.";
      }
    ];
    services.secureResearch = {
      providers.searxng = {
        enable = true;
        capabilities = [ "search" ];
        data = [ "queries" ];
      };
      searchOrder = lib.mkDefault [ "searxng" ];
    };
    users.groups.agent-research-searxng.gid = uid;
    users.users.agent-research-searxng = {
      inherit uid;
      isSystemUser = true;
      group = "agent-research-searxng";
      extraGroups = [ "agent-research" ];
    };
    systemd.sockets.agent-research-searxng = {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "${socketDirectory}/socket" ];
      socketConfig = {
        SocketUser = "root";
        SocketGroup = "agent-research";
        SocketMode = "0660";
        DirectoryMode = "0755";
        RemoveOnStop = true;
      };
    };
    systemd.services.agent-research-searxng = {
      requires = [
        "agent-research-searxng.socket"
        "agent-research-egress.socket"
        "agent-research-egress-control.service"
      ];
      after = [
        "agent-research-searxng.socket"
        "agent-research-egress.socket"
        "agent-research-egress-control.service"
      ];
      serviceConfig = {
        User = "agent-research-searxng";
        Group = "agent-research-searxng";
        SupplementaryGroups = [ "agent-research" ];
        ExecStart = "${cfg.package}/bin/research-searxng --executable ${runner} --client-uid ${toString cfg.serviceUid}";
        RootDirectory = root;
        BindReadOnlyPaths = paths ++ [
          "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt"
          "/run/agent-research-egress"
          socketDirectory
        ];
        PrivateNetwork = true;
        PrivateDevices = true;
        PrivateUsers = false;
        MountAPIVFS = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectProc = "invisible";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        RestrictNamespaces = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        TemporaryFileSystem = [
          "/tmp:rw,nosuid,nodev,noexec,size=134217728,mode=0700,uid=${toString uid}"
        ];
        InaccessiblePaths = [ "/dev/shm" ];
        Slice = "agent-research.slice";
        Delegate = false;
        KillMode = "control-group";
        TimeoutStopSec = 30;
        OOMPolicy = "stop";
        LimitCORE = 0;
        LimitNOFILE = 1024;
        UMask = "0077";
      };
    };
    # Independent host guard: even a host-wide direct exception cannot give
    # this identity a network route outside its private loopback namespace.
    networking.nftables.tables.secure_research_searxng = {
      family = "inet";
      content = ''
        chain output {
          type filter hook output priority -10; policy accept;
          meta skuid ${toString uid} counter drop
        }
        chain postrouting {
          type filter hook postrouting priority 300; policy accept;
          meta skuid ${toString uid} counter drop
        }
      '';
    };
  };
}
