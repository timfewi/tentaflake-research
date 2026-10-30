# Development

Use `devenv shell` for the native default environment, or `devenv shell -- <command>`
for one command. `devenv.nix` reuses the default Flake shell, including its compiler,
build inputs and hooks; `flake.lock` remains the project toolchain pin.
`devenv.yaml` and `devenv.lock` pin the native 2.4.0 runtime separately.
After owner-managed shell-hook activation, review the configuration and explicitly
run `devenv allow` only if you want automatic entry. `nix develop .` and existing
named Flake shells remain available. The bridge uses Git-filtered source: new
source files must be reviewed and Git-tracked before evaluation; never use
`path:.` to copy ignored state into the Nix store. `.devenv/` is local ignored state.

Use the pinned Linux x86_64 Nix shell. Build artifacts must fit on the selected
filesystem; `/tmp` can be too small. Source checks never activate host services or
call paid providers. Fetch locked dependencies once before offline Cargo checks.

```sh
nix develop .
cargo fetch --locked
check_scratch="$(mktemp -d /var/tmp/tentaflake-research-check.XXXXXX)"
TMPDIR="$check_scratch" project-check fast
rmdir "$check_scratch"
cargo test --locked --offline --test service_rpc
cargo test --locked --offline --lib budget::guard::tests
cargo test --locked --offline --lib budget::guard::witness::tests
```

Set `TMPDIR` after entering the pinned shell to keep per-run scratch off `/tmp`.
The pinned check runner overrides `CARGO_TARGET_DIR` with a persistent per-checkout
cache under `$XDG_CACHE_HOME/project-check/` (default `~/.cache/project-check/`).
Without a writable user cache, it falls back to the per-run scratch directory.
The runner removes its scratch after the check; `rmdir` removes only the empty
owned parent. Direct Cargo commands can reuse an explicit `CARGO_TARGET_DIR`.

The guarded-ledger and witness fixtures use temporary directories and synthetic
identities; they do not run the root-only provisioning command or touch service
state. They cover refusal, marker/sidecar consistency, held costs, host state
and ancestor replacement, fresh challenge/peer checks, listener-descriptor
inheritance, and two-worker responsiveness with a stalled witness. Service
fixtures cover start/admission, egress and cancellation races, runtime teardown,
contended receipt settlement, worker failure and independent evidence cleanup.
They do not recreate a real systemd bind mount. Same-UID test processes cannot establish
that a root-created systemd socket passed to a different unprivileged witness UID
actually presents root peer credentials, nor prove host mount visibility,
sandboxing or power-loss behavior. NixOS guarded
admission stays blocked until those properties have been independently reviewed
and accepted on the intended host.

The fast gate runs Rust formatting, all-target/all-feature Clippy with warnings
denied, client-only and default-feature tests, Nix lints/formatting and ShellCheck.
It evaluates the independent client package and rejects service libraries in its
normal Cargo dependency graph. OS fixtures are
compiled but need their own runtime checks. `project-check full` builds the three
Rust package outputs and configuration checks; it does not run every VM.

CI reports the small client separately from service checks and package checks.
The direct client checks cache Cargo targets outside the source tree, keyed by
the locked toolchain and manifests. The source gate uses the runner's separate
persistent Cargo cache rather than the configured outer target directory.
Superseded PR runs are cancelled. No builder or cache account is required by the runtime. An optional
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
