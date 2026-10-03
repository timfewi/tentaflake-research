{
  description = "Isolated public research for local agent harnesses";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/eaad089433ca2bb662274377d33df3d0e51ef28b";
  inputs.project-check = {
    url = "github:timfewi/project-check-nix/f70de45d69b9ca9a31f5b9f94e316ac6e43e514e";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      nixpkgs,
      project-check,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      browserFonts = pkgs.makeFontsConf {
        fontDirectories = [
          pkgs.dejavu_fonts
          pkgs.noto-fonts-color-emoji
        ];
        impureFontDirectories = [ ];
        includes = [ ];
      };
      # Exact runtime closure for the isolated parser's optional OCR phase. It
      # contains the pinned rasterizer and recognizer; the worker only ever sees
      # these store paths read-only. `RESEARCH_TEST_CLOSURE` can point at its
      # `store-paths` file.
      parserClosure = pkgs.closureInfo {
        rootPaths = [
          pkgs.poppler-utils
          pkgs.tesseract
        ];
      };
      package = import ./nix/package.nix { inherit pkgs; };
      clientPackage = import ./nix/package.nix {
        inherit pkgs;
        clientOnly = true;
      };
    in
    {
      nixosModules.default = import ./nix/module.nix { inherit self; };
      packages.${system} = {
        default = package;
        research-service = package;
        research-client = clientPackage;
        research-egress = package.egress;
        research-browser-fonts = browserFonts;
      };
      apps.${system} =
        let
          client = {
            type = "app";
            program = "${clientPackage}/bin/research-client";
          };
        in
        {
          default = client;
          research-client = client;
          secure-research-tool = client;
          research-curl = {
            type = "app";
            program = "${clientPackage}/bin/research-curl";
          };
        };
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.cargo
          pkgs.rustc
          pkgs.rust-analyzer
          pkgs.rustfmt
          pkgs.clippy
          pkgs.pkg-config
          pkgs.sqlite
          pkgs.nixfmt
          pkgs.shellcheck
          pkgs.deadnix
          pkgs.statix
          pkgs.gitleaks
          pkgs.osv-scanner
          project-check.packages.${system}.default
        ];
      };
      formatter.${system} = pkgs.nixfmt;
      checks.${system} = {
        core = package;
        client-packaging = import ./tests/nix/client-packaging.nix { inherit pkgs self; };
        parser-tools = pkgs.runCommand "research-parser-tools-check" { } ''
          for binary in pdfinfo pdftotext pdftoppm; do
            test -x "${pkgs.poppler-utils}/bin/$binary"
          done
          test -x "${pkgs.tesseract}/bin/tesseract"
          cp "${parserClosure}/store-paths" "$out"
        '';
        egress-package = pkgs.runCommand "research-egress-package-check" { } ''
          for binary in research-egress research-egress-control research-vpn-observer; do
            test -x "${package.egress}/bin/$binary"
          done
          touch "$out"
        '';
        network-boundary = import ./tests/nix/network-boundary.nix {
          inherit pkgs nixpkgs;
        };
        network-boundary-vm = import ./tests/nix/network-boundary-vm.nix { inherit pkgs; };
        network-boundary-wireguard-vm = import ./tests/nix/network-boundary-wireguard-vm.nix {
          inherit pkgs self;
        };
        resource-boundary = import ./tests/nix/resource-boundary.nix { inherit pkgs nixpkgs; };
        module = import ./tests/nix/module.nix { inherit pkgs nixpkgs self; };
        module-vm = import ./tests/nix/module-vm.nix { inherit pkgs self; };
        container-clients-vm = import ./tests/nix/container-clients-vm.nix { inherit pkgs nixpkgs self; };
        searxng-vm = import ./tests/nix/searxng-vm.nix { inherit pkgs self; };
        rendering-vm = import ./tests/nix/rendering-vm.nix { inherit pkgs self; };
        parser-credentials-vm = import ./tests/nix/rendering-vm.nix {
          inherit pkgs self;
          withParserProbe = true;
        };
        credentials-vm = import ./tests/nix/module-vm.nix {
          inherit pkgs self;
          withCredentials = true;
        };
        resources-vm = import ./tests/nix/module-vm.nix {
          inherit pkgs self;
          withResources = true;
        };
      };
    };
}
