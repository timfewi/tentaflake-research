# Socket capabilities for OCI agents whose internal UIDs may be identical.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.secureResearch;
  clients = cfg.containerClients;
  userName = name: "tf-research-${builtins.substring 0 12 (builtins.hashString "sha256" name)}";
  unitName = name: "tentaflake-research-${name}";
  socketDirectory = name: "/run/tentaflake-research/${name}";
  # Project only socat's closure and the upstream Unix socket into the relay.
  paths = lib.splitString "\n" (
    lib.removeSuffix "\n" (
      builtins.readFile "${pkgs.closureInfo { rootPaths = [ pkgs.socat ]; }}/store-paths"
    )
  );
  root = pkgs.runCommand "research-container-relay-root" { } ''
    mkdir -p "$out"/{dev/shm,proc,sys,tmp,var/tmp,home,root,etc,nix/store,run/agent-research}
    for path in ${lib.escapeShellArgs paths}; do
      if test -d "$path"; then mkdir -p "$out$path"; else
        mkdir -p "$(dirname "$out$path")"
        touch "$out$path"
      fi
    done
  '';
in
{
  options.services.secureResearch.containerClients = lib.mkOption {
    default = { };
    description = ''
      Per-container Unix relays. Bind only /run/tentaflake-research/NAME read-only
      into that container. The socket is writable inside this capability directory,
      whose host parent is root-only. Each relay uses a distinct host UID for job
      ownership; container UIDs do not become upstream client identities.
    '';
    type = lib.types.attrsOf (
      lib.types.submodule {
        options.uid = lib.mkOption {
          type = lib.types.ints.between 1 4294967294;
          description = "Dedicated non-root host UID, distinct from every other research client and host user.";
        };
      }
    );
  };

  config = lib.mkIf (cfg.enable && clients != { }) {
    assertions = [
      {
        assertion = lib.all (name: builtins.match "[a-z0-9][a-z0-9-]{0,62}" name != null) (
          lib.attrNames clients
        );
        message = "Research container names must be bounded lowercase socket-safe names.";
      }
      {
        assertion =
          lib.length (lib.unique (lib.attrValues cfg.clients)) == lib.length (lib.attrValues cfg.clients);
        message = "Research container relays require distinct upstream client UIDs.";
      }
      {
        assertion = lib.all (
          name:
          lib.all (
            other: other == userName name || (config.users.users.${other}.uid or null) != clients.${name}.uid
          ) (lib.attrNames config.users.users)
        ) (lib.attrNames clients);
        message = "Research relay UIDs must not be shared with other host users.";
      }
    ];
    services.secureResearch.clients = lib.mapAttrs' (
      name: client: lib.nameValuePair (userName name) client.uid
    ) clients;
    users.users = lib.mapAttrs' (
      name: client:
      lib.nameValuePair (userName name) {
        inherit (client) uid;
        isSystemUser = true;
        group = userName name;
        extraGroups = [ cfg.socketGroup ];
      }
    ) clients;
    users.groups = lib.mapAttrs' (name: _: lib.nameValuePair (userName name) { }) clients;
    systemd.tmpfiles.rules = [
      "d /run/tentaflake-research 0700 root root -"
    ]
    ++ lib.mapAttrsToList (name: _: "d ${socketDirectory name} 0755 root root -") clients;
    systemd.sockets = lib.mapAttrs' (
      name: _:
      lib.nameValuePair (unitName name) {
        wantedBy = [ "sockets.target" ];
        partOf = [ "agent-research.socket" ];
        requires = [ "agent-research.socket" ];
        after = [
          "systemd-tmpfiles-setup.service"
          "agent-research.socket"
        ];
        listenStreams = [ "${socketDirectory name}/socket" ];
        socketConfig = {
          Accept = true;
          SocketUser = "root";
          SocketGroup = "root";
          SocketMode = "0666";
          DirectoryMode = "0755";
          MaxConnections = 4;
          Backlog = 4;
          RemoveOnStop = true;
        };
      }
    ) clients;
    systemd.services = lib.mapAttrs' (
      name: _:
      lib.nameValuePair "${unitName name}@" {
        description = "Private research socket relay for ${name}";
        requires = [ "agent-research.socket" ];
        after = [ "agent-research.socket" ];
        partOf = [ "${unitName name}.socket" ];
        serviceConfig = {
          Type = "exec";
          User = userName name;
          Group = userName name;
          SupplementaryGroups = [ cfg.socketGroup ];
          ExecStart = "${pkgs.socat}/bin/socat STDIO UNIX-CONNECT:/run/agent-research/socket";
          StandardInput = "socket";
          StandardOutput = "socket";
          StandardError = "null";
          RootDirectory = root;
          BindReadOnlyPaths = paths ++ [ "/run/agent-research" ];
          PrivateNetwork = true;
          RestrictAddressFamilies = [ "AF_UNIX" ];
          IPAddressDeny = "any";
          PrivateDevices = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          ProtectProc = "invisible";
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          NoNewPrivileges = true;
          CapabilityBoundingSet = "";
          UMask = "0077";
          Slice = "agent-research.slice";
          Delegate = false;
          MemoryMax = "64M";
          MemorySwapMax = "0";
          TasksMax = 16;
          LimitNOFILE = 64;
          LimitCORE = 0;
          TimeoutStopSec = 10;
          KillMode = "control-group";
        };
      }
    ) clients;
  };
}
