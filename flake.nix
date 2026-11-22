{
  description = "Portable signed Git evidence core and CLI";

  # Preserve the frozen Python oracle while Buck uses its provider's own toolchain.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/4ba99f3209788ed04f01af38f77ddb803ad6ec63";
  # Published products for source c64e2880cd9d6631d75cd5e4bf304a762ea3e50f.
  inputs.effect-utils.url = "github:overengineeringstudio/effect-utils/6aa1938b54cab9a986d456a074b19f0cc8fe96fe";
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
      # Independent of the production fixture input: oracle provenance survives its removal.
      python-keys-oracle = builtins.fetchTree {
        type = "git";
        url = "https://github.com/compoundingtech/fractal";
        rev = "787e8ed592dff34d2bdc2a2b0b584482da567e7f";
        narHash = "sha256-EYnLgrxDCQXThOybpPxr2okTy7BpcHkzjLvBsaAZ+vM=";
        shallow = true;
      };
      # The locked nixpkgs owns the CPython source hash; never follow its python3 alias.
      oraclePythonFor = pkgs:
        assert pkgs.python314.version == "3.14.7";
        pkgs.python314;
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
          nativeCheckInputs = [ pkgs.git pkgs.openssh pkgs.openssl pkgs.coreutils ];
          preCheck = ''
            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
          '';
          # Oracle-backed tests belong to checks.evidence, not the production package.
          doCheck = false;
          # Keep vendored native crates (aws-lc-sys) under consumers' cargoUseSystemLibs hook.
          dontCargoUseSystemLibs = true;
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
          dontCargoUseSystemLibs = true;
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
          oracle-python = oraclePythonFor pkgs;
          # Native musl headers/libs plus compiler/binutils wrappers, never host glibc.
          release-musl-toolchain = pkgs.runCommand "mergemaster-musl-toolchain" {} ''
            mkdir -p "$out/bin"
            ln -s ${cc}/bin/${cc.targetPrefix}cc "$out/bin/musl-gcc"
            ln -s ${cc.bintools}/bin/${cc.bintools.targetPrefix}ar "$out/bin/musl-ar"
          '';
        });
      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          oraclePython = oraclePythonFor pkgs;
        in {
          oracle-python = pkgs.runCommand "mergemaster-oracle-python" {
            MERGEMASTER_ORACLE_PYTHON = "${oraclePython}/bin/python3.14";
          } ''
            "$MERGEMASTER_ORACLE_PYTHON" -I -c \
              "import sys; assert sys.implementation.name == 'cpython'; assert sys.version_info[:3] == (3,14,7); assert sys.flags.optimize == 0; assert sys.flags.isolated == 1"
            touch "$out"
          '';
          package-version =
            let package = packageFor system;
            in assert package.version == cargoVersion;
            pkgs.runCommand "mergemaster-package-version" {} ''
              test "$(${pkgs.lib.getExe package} --version)" = "mergemaster ${cargoVersion}"
              touch "$out"
            '';
          evidence = (packageFor system).overrideAttrs (_: {
            doCheck = true;
            nativeCheckInputs = [ pkgs.git pkgs.openssh pkgs.openssl pkgs.coreutils oraclePython ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.strace ];
            MERGEMASTER_ORACLE_PYTHON = "${oraclePython}/bin/python3.14";
            MERGEMASTER_PYTHON_KEYS_ORACLE = "${python-keys-oracle}";
            MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
            MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
            MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
          });
          oracle-corpus = pkgs.runCommand "mergemaster-oracle-corpus" {
            nativeBuildInputs = [ pkgs.git pkgs.openssh ];
            src = self;
            MERGEMASTER_BIN = "${packageFor system}/bin/mergemaster";
            MERGEMASTER_ORACLE_PYTHON = "${oraclePython}/bin/python3.14";
            MERGEMASTER_PYTHON_KEYS_ORACLE = "${python-keys-oracle}";
            MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
            MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
          } ''
            ${oraclePython}/bin/python3 -I -B "$src/tests/oracle_corpus.py"
            touch "$out"
          '';
          oracle-scripts = pkgs.runCommand "mergemaster-oracle-scripts" {
            nativeBuildInputs = [ oraclePython pkgs.git ];
            MERGEMASTER_ORACLE_PYTHON = "${oraclePython}/bin/python3.14";
            MERGEMASTER_PYTHON_KEYS_ORACLE = "${python-keys-oracle}";
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
        let
          pkgs = import effect-utils.inputs.nixpkgs { inherit system; };
          rustPkgs = import nixpkgs { inherit system; };
          oraclePython = oraclePythonFor rustPkgs;
          effectUtilsPackages = effect-utils.packages.${system};
          # Inject the production compiler through the provider's capability renderer.
          # Its unrelated wasm tools retain provider pins; native tools use root nixpkgs.
          rustCapability = import "${effect-utils}/nix/workspace-tools/lib/buck2-rust-toolchain-capability.nix" {
            pkgs = rustPkgs // {
              inherit (pkgs) binaryen;
              "wasm-bindgen-cli_0.2.127" = pkgs."wasm-bindgen-cli_0.2.127";
            };
            nixpkgsRevision = nixpkgs.rev;
          };
          capabilities = import "${effect-utils}/nix/buck2-capabilities.nix" {
            inherit pkgs;
            src = effect-utils;
            inherit (effectUtilsPackages.buck2-capabilities) extraCapabilities;
            capabilityPackages = effectUtilsPackages.buck2-capabilities.capabilityPackages
              // pkgs.lib.mapAttrs' (name: value: pkgs.lib.nameValuePair "buck2-${name}" value)
                rustCapability.packages;
          };
          # Same consumer-root renderer and cell materialization as Fractal
          # 2b0246c95a28f3c4f43b4d6fd87ad50e8e5d05cd:nix/web-shell.nix.
          # flake.lock pins the rules, capabilities and Buck2 to one effect-utils revision.
          buckRoot = effect-utils.lib.mkConsumerBuckRoot {
            inherit pkgs;
            rules = effectUtilsPackages.buck2-rules;
            inherit capabilities;
            cellName = "mergemaster";
            projectIgnore = [
              "**/__pycache__" "**/dist" "**/node_modules" "**/target"
              ".devenv" ".git" "buck-out" "node_modules" "repos" "target" "tmp"
            ];
          };
          # Fractal's test-provider extension, on top of the shared root renderer.
          rootBuckWithTests = pkgs.writeText "mergemaster-root-BUCK" (buckRoot.rootBuck + "\n" + ''
            load("@prelude//tests:test_toolchain.bzl", "noop_test_toolchain")
            load("@prelude//toolchains:remote_test_execution.bzl", "remote_test_execution_toolchain")
            noop_test_toolchain(name = "test", visibility = ["PUBLIC"])
            remote_test_execution_toolchain(name = "remote_test_execution", visibility = ["PUBLIC"])

            load(":buck2/resource-exports.bzl", "export_cargo_resources")
            export_cargo_resources()
          '');
          buckShell = {
            packages = [
              pkgs.watchman effectUtilsPackages.buck2 pkgs.bun rustPkgs.cargo rustPkgs.rustc
              pkgs.jq pkgs.time
              (import "${effect-utils}/nix/reindeer.nix" { inherit pkgs; })
            ] ++ scriptInputs pkgs;
            BUCK2_BIN = "${effectUtilsPackages.buck2}/bin/buck2";
            MERGEMASTER_BUCK_ROOT = "${buckRoot}";
            MERGEMASTER_EFFECT_UTILS = "${effect-utils}";
            MERGEMASTER_RUSTC = "${rustPkgs.rustc}/bin/rustc";
            MERGEMASTER_BUCK_RUSTC = rustCapability.tools.rust-compiler;
            shellHook = ''
              # Consumer files come from the shared renderer, not a second configuration.
              ${pkgs.diffutils}/bin/cmp BUCK ${rootBuckWithTests} || exit 1
              for file in .buckconfig buck2/toolchains/BUCK .watchmanconfig; do
                if ! ${pkgs.diffutils}/bin/cmp "$file" "${buckRoot}/$file"; then
                  echo "Buck2 consumer file differs from pinned mkConsumerBuckRoot: $file" >&2
                  exit 1
                fi
              done
              mkdir -p .buck2
              ln -sfn ${buckRoot}/.buck2/rules .buck2/rules
              ln -sfn ${buckRoot}/.buck2/capabilities .buck2/capabilities
            '';
          };
        in { default = pkgs.mkShell {
          packages = [
            rustPkgs.cargo rustPkgs.rustc rustPkgs.rustfmt rustPkgs.clippy oraclePython
          ] ++ buckShell.packages ++ scriptInputs pkgs;
          inherit (buckShell) BUCK2_BIN MERGEMASTER_BUCK_ROOT shellHook;
          MERGEMASTER_ORACLE_PYTHON = "${oraclePython}/bin/python3.14";
          MERGEMASTER_PYTHON_KEYS_ORACLE = "${python-keys-oracle}";
          # Copied script tests execute the local Rust-backed evidence gate.
          # Provision the matching built binary for every child test process.
          MERGEMASTER_BIN = "${packageFor system}/bin/mergemaster";
          MERGEMASTER_EFFECT_UTILS = "${effect-utils}";
          MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
          MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
          MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
        };
          # Resolving Buck2's toolchain must not first build the Cargo application.
          buck2 = pkgs.mkShell buckShell;
          buck2-evidence = pkgs.mkShell (buckShell // {
            MERGEMASTER_ORACLE_PYTHON = "${oraclePython}/bin/python3.14";
            MERGEMASTER_PYTHON_KEYS_ORACLE = "${python-keys-oracle}";
            MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
            MERGEMASTER_PYTHON_ORACLE = "${python-oracle}";
            MERGEMASTER_PYTHON_PARITY_ORACLE = "${python-oracle-parity}";
            packages = buckShell.packages ++ [ oraclePython ];
          });
        });
    };
}
