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

  outputs = { self, nixpkgs, effect-utils, fractal-fixture }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      scriptInputs = pkgs: with pkgs; [
        effect-utils.packages.${pkgs.stdenv.hostPlatform.system}.genie
        (python3.withPackages (packages: [ packages.pyyaml ])) git openssh bash coreutils findutils gnugrep gnused gawk nix
        nodejs typescript oxfmt
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
      checks = forAllSystems (system: {
        evidence = self.packages.${system}.default;
      });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc ] ++ scriptInputs pkgs;
          MERGEMASTER_EFFECT_UTILS = "${effect-utils}";
          MERGEMASTER_FRACTAL_FIXTURE = "${fractal-fixture}";
        }; });
    };
}
