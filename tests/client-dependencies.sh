#!/usr/bin/env bash
set -euo pipefail

# Service-only libraries must not return to the normal client dependency graph.
# Dev dependencies are excluded: socket fixtures need process/tempfile support.
client_dependencies="$(cargo tree --locked --offline --no-default-features \
  --edges normal,build --prefix none --format '{p}')"
while read -r package _; do
  case "$package" in
    chromiumoxide | chromiumoxide_types | reqwest | rustls | hickory-resolver | \
      rusqlite | dom_query | dom_smoothie)
      printf 'client unexpectedly depends on service library: %s\n' "$package" >&2
      exit 1
      ;;
  esac
done <<< "$client_dependencies"
