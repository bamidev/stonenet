{
  description = "Stonenet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachSystem flake-utils.lib.allSystems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        stdenv = pkgs.stdenv;
        stonenet = pkgs.rustPlatform.buildRustPackage rec {
          pname = "stonenet";
          version = "0.0.0";
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "ed448-rust-0.1.1" = "sha256-AnC3lAIJjnQ6VlZXpjVG/qpPBEIgbJS1/p4200XKCkc=";
            };
          };
          src = pkgs.lib.cleanSource ./.;
        };
      in {
        apps.default = {
          name = "stonenet";
          type = "app";
          program = "${stonenet}/bin/stonenetd";
        };
      });
}
