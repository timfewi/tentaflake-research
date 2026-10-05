{
  lib,
  root ? ../.,
}:
let
  excludedDirectories = [
    "target"
    "node_modules"
    "__pycache__"
    "result"
  ];
  sourceFiles =
    directory:
    let
      entries = builtins.readDir directory;
    in
    lib.concatMap (
      name:
      let
        path = directory + "/${name}";
        kind = entries.${name};
      in
      if lib.hasPrefix "." name || lib.hasPrefix "result-" name then
        [ ]
      else if kind == "directory" then
        if lib.elem name excludedDirectories || (directory == tests && name == "nix") then
          [ ]
        else
          sourceFiles path
      else if kind == "regular" && lib.hasSuffix ".rs" name then
        [ path ]
      else
        [ ]
    ) (builtins.attrNames entries);
  rootEntries = builtins.readDir root;
  src = root + "/src";
  tests = root + "/tests";
  browser = src + "/browser";
  regular = directory: name: ((builtins.readDir directory).${name} or null) == "regular";
in
assert lib.assertMsg (
  (rootEntries.src or null) == "directory" && (rootEntries.tests or null) == "directory"
) "Research source roots must be real directories";
assert lib.assertMsg (
  regular root "Cargo.toml" && regular root "Cargo.lock"
) "Research Cargo inputs must be regular files";
assert lib.assertMsg (
  ((builtins.readDir src).browser or null) == "directory" && regular browser "read.js"
) "The embedded browser script must be a regular file in a real directory";
lib.fileset.toSource {
  inherit root;
  fileset = lib.fileset.unions (
    [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (browser + "/read.js")
    ]
    ++ sourceFiles src
    ++ sourceFiles tests
  );
}
