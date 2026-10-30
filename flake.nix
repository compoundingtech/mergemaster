{
  description = "Portable signed Git evidence core and CLI";

  # Genie shares effect-utils' pinned Buck toolchain and nixpkgs authority.
  inputs.nixpkgs.follows = "effect-utils/nixpkgs";
  inputs.effect-utils.url = "github:overengineeringstudio/effect-utils/d883d18e3ad7609602db0ec8687c14a77625b905";

  outputs = { self, nixpkgs, effect-utils }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      scriptInputs = pkgs: with pkgs; [
        effect-utils.packages.${pkgs.stdenv.hostPlatform.system}.genie
        python3 git openssh bash coreutils findutils gnugrep gnused gawk
        gnutar gzip bzip2 xz zstd jq curl diffutils util-linux procps which time
      ];
      packageFor = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.rustPlatform.buildRustPackage {
          pname = "mergemaster";
          version = "0.1.0";
          src = pkgs.lib.cleanSource self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeCheckInputs = [ pkgs.git pkgs.openssh pkgs.coreutils pkgs.python3 ];
          preCheck = ''
            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
          '';
          doCheck = true;
          meta = {
            description = "Portable signed gate observations in immutable Git notes";
            license = pkgs.lib.licenses.mit;
            mainProgram = "mergemaster";
            platforms = systems;
          };
        };
    in {
      packages = forAllSystems (system: { default = packageFor system; });
      checks = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          evidence = self.packages.${system}.default;
          scripts = pkgs.runCommand "mergemaster-script-tests" {
            nativeBuildInputs = scriptInputs pkgs;
          } ''
            export HOME="$TMPDIR/home"
            export CI_PARALLEL_TESTS_KEEP="$TMPDIR/script-test-logs"
            export MERGEMASTER_EFFECT_UTILS=${effect-utils}
            mkdir -p "$HOME"
            bash ${pkgs.lib.cleanSource self}/scripts/test-scripts
            touch "$out"
          '';
        });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc ] ++ scriptInputs pkgs;
          MERGEMASTER_EFFECT_UTILS = "${effect-utils}";
        }; });
    };
}
