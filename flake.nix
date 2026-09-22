{
  description = "Curvy rs-sdk — Groth16 proving artifacts as a Nix package";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # The release the zkeys are downloaded from is this checkout's own version, so a tagged
      # commit always fetches the assets that were published alongside it. Building an untagged
      # commit whose release has not been cut yet fails at fetch time, which is the right signal.
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
      release = "v${version}";

      # `curvy-witnesscalc/src/lib.rs` is the source of truth for which files make up the artifact
      # set and what they must hash to; the same pins `scripts/fetch-keys.sh` reads. Read them out
      # of the source here too, so a circuit change is one edit and the flake cannot drift from
      # what the crate will accept at load time.
      circuits =
        let
          src = builtins.readFile ./curvy-witnesscalc/src/lib.rs;
          grab =
            field:
            map builtins.head (builtins.filter builtins.isList (builtins.split "${field}: \"([^\"]*)\"" src));
        in
        {
          zkeys = nixpkgs.lib.zipListsWith (name: sha256: { inherit name sha256; }) (grab "zkey_file") (
            grab "zkey_sha256"
          );
          graphs = grab "graph_file";
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs) lib;

          # The five zkeys (~290 MB) are too large for git or a crate and ship as release assets;
          # each is a fixed-output fetch, so a wrong or stale file fails at build time here rather
          # than at load time in a consumer. The five witness graphs are checked in under
          # `artifacts/signet` and come straight from the source tree.
          zkey =
            { name, sha256 }:
            pkgs.fetchurl {
              inherit name sha256;
              url = "https://github.com/0xCurvy/rs-sdk/releases/download/${release}/${name}";
            };
        in
        rec {
          # One flat directory with every zkey and witness graph, the layout `CURVY_ZK_KEYS_DIR`
          # expects. Consumers point the variable at the store path or link it wherever they like.
          curvy-zk-artifacts = pkgs.runCommand "curvy-zk-artifacts-${version}" { } ''
            mkdir -p "$out"
            ${lib.concatMapStringsSep "\n" (z: ''ln -s "${zkey z}" "$out/${z.name}"'') circuits.zkeys}
            ${lib.concatMapStringsSep "\n" (
              g: ''ln -s "${./artifacts/signet + "/${g}"}" "$out/${g}"''
            ) circuits.graphs}
          '';
          default = curvy-zk-artifacts;
        }
      );
    };
}
