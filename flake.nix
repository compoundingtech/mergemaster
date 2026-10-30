{
  description = "Portable signed Git evidence core and CLI";

  # Genie shares effect-utils' pinned Buck toolchain and nixpkgs authority.
  inputs.nixpkgs.follows = "effect-utils/nixpkgs";
  inputs.effect-utils.url = "github:overengineeringstudio/effect-utils/d883d18e3ad7609602db0ec8687c14a77625b905";
  inputs.effect-utils.inputs.nixpkgs.url = "github:NixOS/nixpkgs/4ba99f3209788ed04f01af38f77ddb803ad6ec63";
  inputs.effect-utils.inputs.tsgo.inputs.nixpkgsUnstable.url = "github:NixOS/nixpkgs/44a91898084f46797b5fac650c7e8c9ac38c43d4";

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
        let
          pkgs = import nixpkgs { inherit system; };
          # st-test deliberately normalizes child PATH to fixed system paths.
          # Give those paths real tools, rather than bypassing that behavior.
          fixtureSystemPath = pkgs.buildEnv {
            name = "mergemaster-fixture-system-path";
            paths = with pkgs; [ bash coreutils findutils git openssh python3 ];
            pathsToLink = [ "/bin" ];
          };
        in {
          evidence = self.packages.${system}.default;
          scripts = pkgs.runCommand "mergemaster-script-tests" {
            nativeBuildInputs = scriptInputs pkgs ++ [ pkgs.bubblewrap ];
          } ''
            export HOME="$TMPDIR/home"
            export CI_PARALLEL_TESTS_KEEP="$TMPDIR/script-test-logs"
            export MERGEMASTER_EFFECT_UTILS=${effect-utils}
            mkdir -p "$HOME"
            # Original Fractal tests create executable fixtures and Git hooks
            # with /usr/bin/env shebangs. Match its hermetic FHS test root.
            bwrap --bind /nix /nix --bind "$TMPDIR" "$TMPDIR" --ro-bind /etc /etc \
              --dev /dev --proc /proc --tmpfs /tmp \
              --dir /usr/bin --ro-bind ${pkgs.coreutils}/bin/env /usr/bin/env \
              --dir /bin --ro-bind ${pkgs.bash}/bin/sh /bin/sh \
              --ro-bind ${fixtureSystemPath}/bin /run/current-system/sw/bin \
              --unsetenv PYTHONPATH --unshare-net --chdir "$TMPDIR" \
              -- bash ${pkgs.lib.cleanSource self}/scripts/test-scripts
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
