{
  description = "Portable signed Git evidence core and CLI";

  # Genie shares effect-utils' pinned Buck toolchain and nixpkgs authority.
  inputs.nixpkgs.follows = "effect-utils/nixpkgs";
  inputs.effect-utils.url = "github:overengineeringstudio/effect-utils/d883d18e3ad7609602db0ec8687c14a77625b905";
  inputs.effect-utils.inputs.nixpkgs.url = "github:NixOS/nixpkgs/4ba99f3209788ed04f01af38f77ddb803ad6ec63";
  inputs.effect-utils.inputs.tsgo.inputs.nixpkgsUnstable.url = "github:NixOS/nixpkgs/44a91898084f46797b5fac650c7e8c9ac38c43d4";
  inputs.fractal-fixture = {
    url = "github:compoundingtech/fractal/e2721e52463428b4ff655addee129cecd2839763";
    flake = false;
  };
  inputs.python-oracle = {
    url = "github:compoundingtech/mergemaster/cff667cd53bdb6c024f9d7a06259b8f9a3fbb0cb";
    flake = false;
  };
  # The Python parity reporter was retired before the main oracle's v0.6.0 pin.
  inputs.python-oracle-parity = {
    url = "github:compoundingtech/mergemaster/1392a516e969be46d9516d904b76a4db98c55030";
    flake = false;
  };

  outputs = { self, nixpkgs, effect-utils, fractal-fixture, python-oracle, python-oracle-parity }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      scriptInputs = pkgs: with pkgs; [
        effect-utils.packages.${pkgs.stdenv.hostPlatform.system}.genie
        (python3.withPackages (packages: [ packages.pyyaml ])) git openssh openssl bash coreutils findutils gnugrep gnused gawk nix
        nodejs typescript oxfmt
        gnutar gzip bzip2 xz zstd jq curl diffutils util-linux procps which time
      ];
      packageFor = system:
        let pkgs = import nixpkgs { inherit system; };
        in pkgs.rustPlatform.buildRustPackage {
          pname = "mergemaster";
          version = "0.6.0";
          src = pkgs.lib.cleanSource self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeCheckInputs = [ pkgs.git pkgs.openssh pkgs.openssl pkgs.coreutils pkgs.python3 ];
          preCheck = ''
            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
          '';
          # Oracle-backed tests belong to checks.evidence, not the production package.
          doCheck = false;
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
          evidence = (packageFor system).overrideAttrs (_: {
            doCheck = true;
            MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
            MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
            MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
          });
          oracle-scripts = pkgs.runCommand "mergemaster-oracle-scripts" {
            nativeBuildInputs = [ pkgs.python3 ];
            # Inspect every Git-source entry, including names cleanSource excludes.
            src = self;
            MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
          } ''
            python3 -B "$src/tests/test-oracle-scripts.py"
            python3 -B "$src/tests/oracle_scripts.py"
            touch "$out"
          '';
          fmt = pkgs.runCommand "mergemaster-fmt" {
            nativeBuildInputs = [ pkgs.cargo pkgs.rustfmt ];
            src = pkgs.lib.cleanSource self;
          } ''
            cp -r "$src" source
            chmod -R u+w source
            cd source
            cargo fmt --all --check
            touch "$out"
          '';
          clippy = (packageFor system).overrideAttrs (old: {
            pname = "mergemaster-clippy";
            nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.clippy ];
            buildPhase = ''
              runHook preBuild
              cargo clippy --locked --offline --all-targets -- -D warnings
              runHook postBuild
            '';
            doCheck = false;
            installPhase = ''mkdir -p "$out"'';
          });
        });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc pkgs.rustfmt pkgs.clippy ] ++ scriptInputs pkgs;
          MERGEMASTER_EFFECT_UTILS = "${effect-utils}";
          MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
          MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
          MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
        }; });
    };
}
