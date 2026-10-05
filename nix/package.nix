{
  pkgs,
  clientOnly ? false,
}:
let
  inherit (pkgs) lib;
  clientTargets = [
    "--bin"
    "research-client"
    "--bin"
    "research-curl"
  ];
in
pkgs.rustPlatform.buildRustPackage (
  {
    pname = "secure-research";
    version = "0.1.0";
    src =
      if clientOnly then
        lib.fileset.toSource {
          root = ../.;
          fileset = lib.fileset.unions [
            ../Cargo.toml
            ../Cargo.lock
            ../src/api.rs
            ../src/bridge.rs
            ../src/config.rs
            ../src/error.rs
            ../src/lib.rs
            ../src/mcp.rs
            ../src/policy.rs
            ../src/protocol.rs
            ../src/bin/research-client.rs
            ../src/bin/research-curl.rs
            ../tests/client_transport.rs
          ];
        }
      else
        import ./source.nix { inherit lib; };
    cargoLock.lockFile = ../Cargo.lock;
    outputs = [
      "out"
      "client"
      "egress"
    ];
    strictDeps = true;
    nativeBuildInputs = [ pkgs.pkg-config ];
    postInstall = ''
      mkdir -p "$client/bin" "$egress/bin"
      mv "$out/bin/research-client" "$client/bin/"
      mv "$out/bin/research-curl" "$client/bin/"
      mv "$out/bin/research-egress" "$egress/bin/"
      mv "$out/bin/research-egress-control" "$egress/bin/"
      mv "$out/bin/research-vpn-observer" "$egress/bin/"
    '';
    meta = {
      platforms = [ pkgs.stdenv.hostPlatform.system ];
      license = lib.licenses.mit;
      homepage = "https://github.com/timfewi/tentaflake-research";
      description = "Isolated, bounded public research for AI agents";
    };
  }
  // lib.optionalAttrs clientOnly {
    pname = "secure-research-client";
    outputs = [ "out" ];
    nativeBuildInputs = [ ];
    buildNoDefaultFeatures = true;
    cargoBuildFlags = clientTargets;
    cargoTestFlags = clientTargets ++ [
      "--lib"
      "--test"
      "client_transport"
    ];
    postInstall = ''
      test -x "$out/bin/research-client"
      test -x "$out/bin/research-curl"
      install -Dm644 ${../LICENSE} "$out/share/licenses/secure-research-client/LICENSE"
    '';
    meta = {
      description = "Provider-independent stdio and GET clients for isolated research";
      license = lib.licenses.mit;
      platforms = [ pkgs.stdenv.hostPlatform.system ];
      mainProgram = "research-client";
    };
  }
)
