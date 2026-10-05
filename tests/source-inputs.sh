#!/usr/bin/env bash
set -euo pipefail

task_root=$(mktemp -d)
trap 'rm -rf -- "$task_root"' EXIT
task_fixture="$task_root/source fixture"
mkdir -p "$task_fixture/src/browser" "$task_fixture/src/nix" "$task_fixture/tests/nix"
printf '[package]\nname = "fixture"\nversion = "0.0.0"\n' > "$task_fixture/Cargo.toml"
printf 'version = 4\n' > "$task_fixture/Cargo.lock"
printf 'pub fn fixture() {}\n' > "$task_fixture/src/lib.rs"
printf 'pub fn nested() {}\n' > "$task_fixture/src/nix/mod.rs"
printf 'const fixture = true;\n' > "$task_fixture/src/browser/read.js"
printf '#[test] fn fixture() {}\n' > "$task_fixture/tests/fixture.rs"
printf '{}\n' > "$task_fixture/tests/nix/fixture.nix"

source_path() {
  timeout 30 env NIX_PATH= RESEARCH_SOURCE_FIXTURE="$task_fixture" \
    nix eval --offline --no-write-lock-file --impure --raw --expr '
      let f = builtins.getFlake (toString ./.); in toString (import ./nix/source.nix {
        lib = f.inputs.nixpkgs.lib;
        root = /. + builtins.getEnv "RESEARCH_SOURCE_FIXTURE";
      })'
}

task_baseline=$(source_path)
test -f "$task_baseline/src/lib.rs"
test -f "$task_baseline/src/nix/mod.rs"
test -f "$task_baseline/src/browser/read.js"
test -f "$task_baseline/tests/fixture.rs"
test ! -e "$task_baseline/tests/nix"

mkdir -p "$task_fixture/src/.cache" "$task_fixture/src/target/generated" \
  "$task_fixture/src/node_modules" "$task_fixture/src/__pycache__" \
  "$task_fixture/src/result" "$task_fixture/src/result-fixture" "$task_fixture/tests/.cache"
printf 'synthetic local state\n' > "$task_fixture/src/credentials.json"
printf 'pub fn stale() {}\n' > "$task_fixture/src/.cache/generated.rs"
printf 'pub fn stale() {}\n' > "$task_fixture/src/target/generated/cache.rs"
for task_directory in node_modules __pycache__ result result-fixture; do
  printf 'pub fn stale() {}\n' > "$task_fixture/src/$task_directory/generated.rs"
done
printf 'pub fn stale() {}\n' > "$task_fixture/tests/.cache/generated.rs"
printf 'synthetic runner output\n' > "$task_fixture/tests/output.txt"
if [[ "$(source_path)" != "$task_baseline" ]]; then
  echo 'Local state or caches changed the packaged source' >&2
  exit 1
fi

printf 'synthetic external contents\n' > "$task_root/external.rs"
ln -s "$task_root/external.rs" "$task_fixture/src/external.rs"
mkdir "$task_root/external-directory"
printf 'pub fn external() {}\n' > "$task_root/external-directory/mod.rs"
ln -s "$task_root/external-directory" "$task_fixture/src/external-directory"
mkfifo "$task_fixture/src/special.rs"
test "$(source_path)" = "$task_baseline"

assert_rejected() {
  if source_path > "$task_root/rejected.out" 2> "$task_root/rejected.err"; then
    echo 'A required source input followed a symlink' >&2
    exit 1
  fi
  [[ "$(< "$task_root/rejected.err")" == *"$1"* ]]
}

mv "$task_fixture/src/browser/read.js" "$task_root/read.js"
ln -s "$task_root/read.js" "$task_fixture/src/browser/read.js"
assert_rejected 'The embedded browser script must be a regular file in a real directory'
rm "$task_fixture/src/browser/read.js"
mv "$task_root/read.js" "$task_fixture/src/browser/read.js"

mv "$task_fixture/tests" "$task_root/test-directory"
ln -s "$task_root/test-directory" "$task_fixture/tests"
assert_rejected 'Research source roots must be real directories'
rm "$task_fixture/tests"
mv "$task_root/test-directory" "$task_fixture/tests"

mv "$task_fixture/Cargo.toml" "$task_root/Cargo.toml"
ln -s "$task_root/Cargo.toml" "$task_fixture/Cargo.toml"
assert_rejected 'Research Cargo inputs must be regular files'
rm "$task_fixture/Cargo.toml"
mv "$task_root/Cargo.toml" "$task_fixture/Cargo.toml"

printf 'pub fn edited() {}\n' >> "$task_fixture/src/lib.rs"
task_code=$(source_path)
test "$task_code" != "$task_baseline"
printf '#[test] fn edited() {}\n' >> "$task_fixture/tests/fixture.rs"
task_test=$(source_path)
test "$task_test" != "$task_code"
printf 'const edited = true;\n' >> "$task_fixture/src/browser/read.js"
task_script=$(source_path)
test "$task_script" != "$task_test"
printf '# changed lock\n' >> "$task_fixture/Cargo.lock"
test "$(source_path)" != "$task_script"
echo 'Rust, embedded script and lock edits invalidate source; local state is excluded and required symlinks are rejected.'
