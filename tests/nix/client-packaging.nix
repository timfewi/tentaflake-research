{ pkgs, self }:
let
  client = self.packages.${pkgs.stdenv.hostPlatform.system}.research-client;
  service = self.packages.${pkgs.stdenv.hostPlatform.system}.research-service;
in
assert client.pname == "secure-research-client";
assert client.outputs == [ "out" ];
assert client.buildNoDefaultFeatures;
assert builtins.pathExists "${client.src}/src/bin/research-client.rs";
assert builtins.pathExists "${client.src}/src/bin/research-curl.rs";
assert builtins.pathExists "${client.src}/tests/client_transport.rs";
assert !(builtins.pathExists "${client.src}/src/provider.rs");
assert !(builtins.pathExists "${client.src}/src/service.rs");
assert !(builtins.pathExists "${client.src}/src/browser");
assert
  service.outputs == [
    "out"
    "client"
    "egress"
  ];
assert
  self.apps.${pkgs.stdenv.hostPlatform.system}.research-client.program
  == "${client}/bin/research-client";
assert
  self.apps.${pkgs.stdenv.hostPlatform.system}.research-curl.program == "${client}/bin/research-curl";
pkgs.runCommand "research-client-packaging-check" { } "touch $out"
