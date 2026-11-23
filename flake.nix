{
  description = "Private networks for containers across many hosts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { moduleWithSystem, ... }:
      {
        systems = [
          "x86_64-linux"
          "aarch64-linux"
          "aarch64-darwin"
        ];

        perSystem =
          { pkgs, lib, ... }:
          let
            open6pn = pkgs.buildGoModule {
              pname = "open6pn";
              version = inputs.self.shortRev or inputs.self.dirtyShortRev or "dev";
              src = ./.;
              vendorHash = "sha256-WiQJRa2LPogGZ2dOqK86rokfKrwd/hLGoFCcRU42l38=";
              excludedPackages = [ "test/e2e" ];
              env.CGO_ENABLED = 0;
              ldflags = [
                "-s"
                "-w"
              ];
              meta = {
                description = "Private networks for containers across many hosts";
                homepage = "https://github.com/satrobit/open6pn";
                license = lib.licenses.mit;
                platforms = lib.platforms.linux;
                mainProgram = "open6pn";
              };
            };
          in
          {
            packages = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
              inherit open6pn;
              default = open6pn;
            };

            checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
              inherit open6pn;
              nixos = pkgs.testers.runNixOSTest (
                import ./nix/test.nix {
                  module = ./nix/module.nix;
                  package = open6pn;
                }
              );
            };

            devShells.default = pkgs.mkShell {
              packages = [
                pkgs.go
                pkgs.gopls
                pkgs.gnumake
              ];
            };

            formatter = pkgs.nixfmt;
          };

        flake.nixosModules.default = moduleWithSystem (
          { config }:
          { lib, ... }:
          {
            imports = [ ./nix/module.nix ];
            services.open6pn.package = lib.mkDefault config.packages.open6pn;
          }
        );
      }
    );
}
