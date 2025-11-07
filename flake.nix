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
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;

        stonenet = pkgs.rustPlatform.buildRustPackage rec {
          pname = manifest.name;
          version = manifest.version;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "ed448-rust-0.1.1" = "sha256-AnC3lAIJjnQ6VlZXpjVG/qpPBEIgbJS1/p4200XKCkc=";
            };
          };
          src = pkgs.lib.cleanSource ./.;
        };

        stonenet-windows-installer = stdenv.mkDerivation {
          pname = "stonenet-windows-installer";
          version = "0.0.0";
          outputs = ["out"];

          src = pkgs.lib.cleanSource ./.;

          buildInputs = with pkgs; [nsis];

          buildPhase = with pkgs; ''
            ${rustup}/bin/cargo build --release --target=x86_64-pc-windows-gnu
            ${nsis}/bin/makensis package/windows.nsi
          '';

          installPhase = with pkgs; ''
            ${coreutils}/bin/cp installer.exe $out/stonenet-windows-installer.exe
          '';

        };
        
        buildWindowsInstaller = pkgs.writers.writeBashBin "build-windows-installer" (with pkgs; ''
          cargo build --release --target=x86_64-pc-windows-gnu
        '');

      in {
        apps.default = {
          name = "stonenet";
          type = "app";
          program = "${stonenet}/bin/stonenetd";
        };

        devShells.publish = pkgs.mkShell {
          packages = [
            buildWindowsInstaller
          ] ++ (with pkgs; [
            cargo
            nsis
          ]);
        };

        packages.default = stonenet;
      });
}
