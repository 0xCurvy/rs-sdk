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

      # The release the compact zkeys are downloaded from is this checkout's own version, so a
      # tagged commit always fetches the assets that were published alongside it. Building an
      # untagged commit whose release has not been cut yet fails at fetch time.
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
      release = "v${version}";

      # `curvy-witnesscalc/src/lib.rs` is the source of truth for which files make up the artifact
      # set and what they must hash to; the same pins `scripts/fetch-keys.sh` reads. Read them out
      # of the source here too, so a circuit change is one edit and the flake cannot drift from
      # what the crate will accept at load time.
      circuits =
        let
          # The circuit definitions only; the test module's fixtures are not release artifacts.
          src = builtins.head (
            builtins.split "#\\[cfg\\(test\\)\\]" (builtins.readFile ./curvy-witnesscalc/src/lib.rs)
          );
          grab =
            field:
            map builtins.head (builtins.filter builtins.isList (builtins.split "${field}: \"([^\"]*)\"" src));
          names = grab "zkey_file";
          zkeySha256 = grab "zkey_sha256";
          compactSha256 = grab "compact_sha256";
          count = builtins.length names;
        in
        assert builtins.length zkeySha256 == count && builtins.length compactSha256 == count;
        {
          zkeys = builtins.genList (i: {
            name = builtins.elemAt names i;
            sha256 = builtins.elemAt zkeySha256 i;
            compactSha256 = builtins.elemAt compactSha256 i;
          }) count;
          graphs = grab "graph_file";
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs) lib;

          # The decoder that expands a compact zkey: curvy-witnesscalc's `inflate_zkey` example,
          # built from this workspace's Cargo.lock.
          inflate-zkey = pkgs.rustPlatform.buildRustPackage {
            pname = "curvy-inflate-zkey";
            inherit version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "-p"
              "curvy-witnesscalc"
              "--example"
              "inflate_zkey"
            ];
            doCheck = false;
            installPhase = ''
              runHook preInstall
              install -Dm755 "$(find target -type f -path '*/release/examples/inflate_zkey' | head -n 1)" \
                "$out/bin/inflate_zkey"
              runHook postInstall
            '';
          };

          # The five compact zkeys (~62 MB) ship as release assets, each a fixed-output fetch
          # pinned by `compact_sha256`. Each zkey is inflated from its compact zkey into a
          # fixed output pinned by `zkey_sha256`, so a wrong, stale or misdecoded key fails at
          # build time here rather than at load time in a consumer. The five witness graphs are
          # checked in under `artifacts/signet` and come straight from the source tree.
          compactName = name: "${lib.removeSuffix ".zkey" name}.czkey";
          zkey =
            {
              name,
              sha256,
              compactSha256,
            }:
            let
              compact = pkgs.fetchurl {
                name = compactName name;
                sha256 = compactSha256;
                url = "https://github.com/0xCurvy/rs-sdk/releases/download/${release}/${compactName name}";
              };
            in
            pkgs.runCommand name {
              nativeBuildInputs = [ inflate-zkey ];
              outputHashMode = "flat";
              outputHashAlgo = "sha256";
              outputHash = sha256;
            } ''inflate_zkey "${compact}" ${compactSha256} "$out"'';
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
          inherit inflate-zkey;
          default = curvy-zk-artifacts;
        }
      );
    };
}
