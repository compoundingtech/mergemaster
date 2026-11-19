{
  description = "Portable signed Git evidence core and CLI";

  # Genie shares effect-utils' pinned Buck toolchain and nixpkgs authority.
  inputs.nixpkgs.follows = "effect-utils/nixpkgs";
  inputs.effect-utils.url = "github:overengineeringstudio/effect-utils/d883d18e3ad7609602db0ec8687c14a77625b905";
  inputs.effect-utils.inputs.nixpkgs.url = "github:NixOS/nixpkgs/4ba99f3209788ed04f01af38f77ddb803ad6ec63";
  inputs.effect-utils.inputs.tsgo.inputs.nixpkgsUnstable.url = "github:NixOS/nixpkgs/44a91898084f46797b5fac650c7e8c9ac38c43d4";
  inputs.fractal-fixture = {
    url = "git+https://github.com/compoundingtech/fractal?rev=787e8ed592dff34d2bdc2a2b0b584482da567e7f&shallow=1";
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
      cargoVersion = (builtins.fromTOML (builtins.readFile ./crates/mergemaster-evidence/Cargo.toml)).package.version;
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
          version = cargoVersion;
          src = pkgs.lib.cleanSource self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "mergemaster-evidence" ];
          cargoTestFlags = [ "--package" "mergemaster-evidence" ];
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
      reconcilerFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
          runtimeTools = [ pkgs.git pkgs.gh pkgs.openssh pkgs.gnupg ];
        in pkgs.rustPlatform.buildRustPackage {
          pname = "mergemaster-reconciler";
          version = (builtins.fromTOML (builtins.readFile ./crates/mergemaster-reconciler/Cargo.toml)).package.version;
          src = pkgs.lib.cleanSource self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--package" "mergemaster-reconciler" ];
          cargoTestFlags = [ "--package" "mergemaster-reconciler" ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          # Exercise the production subprocess boundary with the wrapper's tools.
          nativeCheckInputs = [ pkgs.openssl ] ++ runtimeTools;
          doCheck = false;
          postInstall = ''
            wrapProgram "$out/bin/mergemaster-reconciler" \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeTools}
          '';
          meta = {
            description = "BASE-authorized GitHub evidence check reconciliation";
            license = pkgs.lib.licenses.mit;
            mainProgram = "mergemaster-reconciler";
            platforms = systems;
          };
        };
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          cc = pkgs.pkgsStatic.stdenv.cc;
        in {
          default = packageFor system;
          evidence-reconciler = reconcilerFor system;
          # Native musl headers/libs plus compiler/binutils wrappers, never host glibc.
          release-musl-toolchain = pkgs.runCommand "mergemaster-musl-toolchain" {} ''
            mkdir -p "$out/bin"
            ln -s ${cc}/bin/${cc.targetPrefix}cc "$out/bin/musl-gcc"
            ln -s ${cc.bintools}/bin/${cc.bintools.targetPrefix}ar "$out/bin/musl-ar"
          '';
        });
      checks = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          package-version =
            let package = packageFor system;
            in assert package.version == cargoVersion;
            pkgs.runCommand "mergemaster-package-version" {} ''
              test "$(${pkgs.lib.getExe package} --version)" = "mergemaster ${cargoVersion}"
              touch "$out"
            '';
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
            MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
          } ''
            python3 -B "$src/tests/test-oracle-scripts.py"
            python3 -B "$src/tests/oracle_scripts.py"
            touch "$out"
          '';
          evidence-reconciler = (reconcilerFor system).overrideAttrs (_: {
            doCheck = true;
          });
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
          # Copied script tests execute the local Rust-backed evidence gate.
          # Provision the matching built binary for every child test process.
          MERGEMASTER_BIN = "${packageFor system}/bin/mergemaster";
          MERGEMASTER_EFFECT_UTILS = "${effect-utils}";
          MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
          MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
          MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
        }; });
    };
}
