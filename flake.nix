{
  description = "Portable signed Git evidence core and CLI";

  # Genie shares effect-utils' pinned Buck toolchain and nixpkgs authority.
  inputs.nixpkgs.follows = "effect-utils/nixpkgs";
  inputs.effect-utils.url = "github:overengineeringstudio/effect-utils/d883d18e3ad7609602db0ec8687c14a77625b905";
  inputs.effect-utils.inputs.nixpkgs.url = "github:NixOS/nixpkgs/4ba99f3209788ed04f01af38f77ddb803ad6ec63";
  inputs.effect-utils.inputs.tsgo.inputs.nixpkgsUnstable.url = "github:NixOS/nixpkgs/44a91898084f46797b5fac650c7e8c9ac38c43d4";
  inputs.fractal-fixture = {
    url = "github:compoundingtech/fractal/e83871ec919f95b3b3e2a9a1cd211c2ac37babda";
    flake = false;
  };
  inputs.python-oracle = {
    url = "github:compoundingtech/mergemaster/1392a516e969be46d9516d904b76a4db98c55030";
    flake = false;
  };

  outputs = { self, nixpkgs, effect-utils, fractal-fixture, python-oracle }:
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
          version = "0.5.0";
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
          });
          oracle-scripts = pkgs.runCommand "mergemaster-oracle-scripts" {
            nativeBuildInputs = [ pkgs.python3 ];
            # Inspect every Git-source entry, including names cleanSource excludes.
            src = self;
            MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
          } ''
            python3 - <<'PY'
            import os
            from pathlib import Path

            scripts = Path(os.environ["src"]) / "scripts"
            oracle = Path(os.environ["MERGEMASTER_PYTHON_ORACLE"]) / "scripts"
            # Repository metadata and orchestration, not copied upstream scripts.
            exempt = {"PROVENANCE", "test-scripts", "parity-drift", "parity-drift-test"}
            for path in sorted(scripts.rglob("*")):
                if path.is_dir() and not path.is_symlink():
                    continue
                relative = path.relative_to(scripts)
                if relative.as_posix() in exempt:
                    continue
                reference = oracle / relative
                if (path.is_symlink() or not reference.is_file()
                        or path.read_bytes() != reference.read_bytes()
                        or (path.stat().st_mode & 0o111) != (reference.stat().st_mode & 0o111)):
                    raise SystemExit(f"scripts/{relative}: differs from pinned oracle or is not an oracle copy")
            PY
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
        }; });
    };
}
