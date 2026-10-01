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
denied, default-feature tests, Nix lints/formatting and ShellCheck. OS fixtures are
compiled but need their own runtime checks. `project-check full` builds the three
Rust package outputs and configuration checks; it does not run every VM.

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

Keep documentation-only files outside the Rust package fileset. Before publication,
review the selected Git diff, run a redacted secret scan and verify documentation
links. Record exactly which source checkpoint and fixture were tested in
[verification.md](verification.md). Do not promote historical passes to a new run.
