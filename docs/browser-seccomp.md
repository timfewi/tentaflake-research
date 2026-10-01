# Browser and parser seccomp: design proposal

Status: hardening investigation. Chromium renderers already use their upstream
sandbox and observed seccomp filters. This proposal concerns an additional
systemd filter around the outer Research service/browser worker and parser
processes; it must not replace namespaces, mount policy, cgroups or Chromium's
own sandbox.

## Design approach

Start from observed syscall requirements under the pinned x86_64 package, then
write an explicit rationale grouped by function rather than copying an Internet
allowlist. Keep browser and parser policies separate. The browser supervisor must
still spawn Chromium and support its sandbox setup; the parser worker needs
Poppler/Tesseract process creation and bounded scratch I/O. Architecture-specific
differences are explicit, and a future aarch64 policy needs its own evidence.

Prefer systemd `SystemCallFilter` groups plus a short reviewed exception list
when they express the intended boundary. Use `SystemCallArchitectures=native`,
retain `NoNewPrivileges`, empty capability bounding sets and existing namespace
restrictions. Deny or constrain kernel attack surfaces with existing systemd
controls where possible. A filter must fail service startup clearly when the
pinned runtime needs a missing syscall; it must never fall back to an unfiltered
process.

The threat model is code execution in the outer worker/parser after a browser or
document-parser escape. The policy should reduce kernel surface and forbid host
administration, namespace creation and unrelated IPC. It cannot contain a kernel
exploit that uses an allowed syscall, and Chromium's large syscall needs limit
the achievable reduction.

## Development sequence

1. Capture syscall inventories only from synthetic real-browser/parser fixtures
   under the pinned packages; do not inspect personal processes or host traces.
2. Normalize results by component and scenario: startup, TLS/network relay,
   HTML, PDF, OCR, frames/workers, cancellation and forced teardown.
3. Propose filters with rationale and negative probes. Review generated systemd
   units before execution.
4. Run every existing browser/parser isolation fixture plus package and module
   checks. Repeat forced failure, timeout and cleanup cases.
5. Add a deployment VM that proves selected forbidden syscalls fail with the
   expected signal/error while normal workloads and Chromium's own sandbox pass.

## Acceptance limits

Passing the current fixtures establishes compatibility only for their paths. It
does not prove completeness for arbitrary sites, PDFs, OCR languages or future
Chromium versions. Package upgrades must invalidate the compatibility evidence
and rerun the suite. Do not claim a seccomp "allowlist" if systemd groups expand
to broad syscall sets; document the actual expanded policy for each architecture.

Open decisions: target components, default-on versus experimental rollout,
failure reporting, syscall inventory tooling inside the Nix fixture, upgrade
policy and the minimum negative probes required for deployment acceptance.
