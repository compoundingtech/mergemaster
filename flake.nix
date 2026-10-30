{
  description = "Portable signed Git evidence core and CLI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
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
      checks = forAllSystems (system: { evidence = self.packages.${system}.default; });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc pkgs.git pkgs.openssh pkgs.python3 pkgs.coreutils ];
        }; });
    };
}
