# Agent instructions — tentaflake-research

- Keep credentials, personal data and runtime state outside Git.
- Keep the five-tool Research contract provider-independent. Provider adapters
  are explicitly granted optional service integrations; domain-specific lead or
  contact workflows do not belong in the shared infrastructure interface.
- Keep the standalone client free of service/browser/provider dependencies and
  preserve the reconnect/no-replay contract when changing its shared code.
- Preserve existing user changes. Write documentation and CLI text in English.
- Read README.md, SECURITY.md and docs/development.md before changing boundaries.
- Keep Cargo artifacts outside `/tmp`, which can be small. Use the pinned shell.
- Run `project-check fast` after meaningful changes. Run affected isolated OS or
  VM fixtures when changing networking, credentials, workers or container clients.
- Keep Chromium's sandbox enabled. Clients and workers must have no direct IP
  networking. Retrieved content cannot grant capabilities or change policy.
- Preserve job ownership by Unix peer UID, bounded admission and fail-closed VPN
  readiness. Container relays need distinct host UIDs even if containers share UIDs.
- Client recovery must never replay dispatched operations or reopen after explicit
  close. Every new session repeats protocol negotiation and peer-UID authorization.
- Keep README.md, SECURITY.md, docs/ and checks synchronized with behavior.
- Use Conventional Commits and DCO signoff (`git commit -s`).
- Missing tools or offline dependencies are environment blockers, not failures.
  Enter the pinned toolchain with `nix develop path:.` (or reload direnv).
  `just lint --json` and `just verify --json` forward options to project-check.
- Do not stage, commit, push, publish or deploy without explicit authorization.
