# Development

Use the pinned Linux x86_64 Nix shell. Build artifacts must fit on the selected
filesystem; `/tmp` can be too small. Source checks never activate host services or
call paid providers. Fetch locked dependencies once before offline Cargo checks.

```sh
nix develop --command cargo fetch --locked
nix develop --command project-check fast
nix develop --command cargo test --locked --offline --test service_rpc
```

The fast gate runs Rust formatting, all-target/all-feature Clippy with warnings
denied, client-only and default-feature tests, Nix lints/formatting and ShellCheck.
It evaluates the independent client package and rejects service libraries in its
normal Cargo dependency graph. OS fixtures are
compiled but need their own runtime checks. `project-check full` builds the three
Rust package outputs and configuration checks; it does not run every VM.

CI reports the small client separately from service checks and package checks.
Cargo target caches are outside the source tree and keyed by the locked toolchain
and manifests; client and service caches are separate. Superseded PR runs are
cancelled. No builder or cache account is required by the runtime. An optional
remote Nix builder (including nixbuild.net) can build packages, but VM fixtures
also need compatible runtime/KVM support; voucher CPU-hours are not runner hours.

Check or build only the socket clients with:

```sh
bash scripts/check client
cargo build --locked --offline --no-default-features --bin research-client --bin research-curl
```

Use the pinned shell for this command. The default `service` Cargo feature keeps
the existing service, egress and worker build. Shared request types and protocol
remain provider-independent; the normal client graph has no Chromium, HTTP/TLS,
DNS, HTML extraction or SQLite libraries. Client package sources exclude
service/provider implementation files, so changes confined to those files do
not invalidate the client package. Fetching sources still uses the shared lockfile.
Use `path:.` when evaluating a working tree containing new, unstaged Nix files.

```sh
nix build --no-link .#research-service .#research-client .#research-egress
nix build --no-link .#checks.x86_64-linux.module
nix build --no-link .#checks.x86_64-linux.network-boundary
nix build --no-link .#checks.x86_64-linux.resource-boundary
```

Boundary changes need the affected VM tests (Linux/KVM recommended):

```sh
nix build -L --no-link .#checks.x86_64-linux.module-vm
nix build -L --no-link .#checks.x86_64-linux.network-boundary-vm
nix build -L --no-link .#checks.x86_64-linux.network-boundary-wireguard-vm
nix build -L --no-link .#checks.x86_64-linux.resources-vm
nix build -L --no-link .#checks.x86_64-linux.credentials-vm
nix build -L --no-link .#checks.x86_64-linux.rendering-vm
nix build -L --no-link .#checks.x86_64-linux.parser-credentials-vm
```

Browser/parser process fixtures in `scripts/check` require the pinned executable
paths and an exact closure file. See [browser-validation.md](browser-validation.md).
Missing isolation prerequisites fail the fixture; do not disable isolation.

The VPN observer fixture (`scripts/check vpn-observer`) needs the pinned
Bubblewrap as `RESEARCH_TEST_BWRAP` and a closure file with glibc and the C++
runtime library as `RESEARCH_TEST_CONTROL_CLOSURE` (a `closureInfo` of
`p.glibc` and `p.stdenv.cc.cc.lib` from the locked nixpkgs, its `store-paths`).
It runs the real observer as namespace-root against synthetic route, rule and
sysfs inputs and never reads host networking; see [vpn-adapters.md](vpn-adapters.md).

The service package source (`nix/source.nix`) admits only regular `.rs` files
under `src` and `tests`, `Cargo.toml`, `Cargo.lock` and the embedded
`src/browser/read.js`. It excludes `tests/nix`, hidden paths, build/cache/result
directories, symlinks and special files, so local state such as credentials or
caches under `src` never enters the Nix store, and it rejects required inputs
supplied through symlinks. Declare any new non-Rust package input in
`nix/source.nix`. `tests/source-inputs.sh` checks this with synthetic files and
runs in `project-check fast`. The client package keeps its explicit file list.

Keep documentation-only files outside the Rust package fileset. Before publication,
review the selected Git diff, run a redacted secret scan and verify documentation
links. Record exactly which source checkpoint and fixture were tested in
[verification.md](verification.md). Do not promote historical passes to a new run.
