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
        desktopManifest = (pkgs.lib.importTOML ./desktop/Cargo.toml).package;

        stonenet = pkgs.rustPlatform.buildRustPackage {
          pname = manifest.name;
          version = manifest.version;
          outputs = ["out" "share"];
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "ed448-rust-0.1.1" = "sha256-AnC3lAIJjnQ6VlZXpjVG/qpPBEIgbJS1/p4200XKCkc=";
            };
          };
          src = pkgs.lib.cleanSource ./.;

          installPhase = with pkgs; ''
            set -e

            ls target/release
            ${coreutils}/bin/mkdir -p $out/bin
            ${coreutils}/bin/cp target/${stdenv.targetPlatform.rust.rustcTargetSpec}/release/stonenetd $out/bin
            ${coreutils}/bin/mkdir -p $share
            ${coreutils}/bin/cp -r static $share
            ${coreutils}/bin/cp -r templates $share
          '';
        };

        /*stonenet-desktop = pkgs.rustPlatform.buildRustPackage {
          pname = manifest.name;
          version = manifest.version;
          cargoLock.lockFile = ./desktop/Cargo.lock; 
          src = pkgs.lib.cleanSource ./desktop;
        };*/

        stonenet-windows-installer = stdenv.mkDerivation {
          pname = manifest.name + "-windows-installer";
          version = manifest.version;
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

        nixosModules.default = { config, lib, pkgs, ... }:
          let
            settingsFormat = pkgs.formats.toml {};
            defaultConfig = pkgs.lib.importTOML ./conf/default.toml;
            effectiveConfig = defaultConfig // config.services.stonenet.config;
            userConfigFile = settingsFormat.generate "stonenet.toml" (
              effectiveConfig
            );
          in {
            options = {
              services.stonenet = {
                enable = lib.mkEnableOption "stonenet";
                
                package = lib.mkOption {
                  description = "Stonenet package to use";
                  type = lib.types.package;
                  default = stonenet;
                };

                desktop = {
                  enable = lib.mkEnableOption "stonenet-desktop";
                };

                config = lib.mkOption {
                  description = "Stonenet configuration file";
                  type = lib.types.attrs;
                  default = {};
                };
              };
            };
            config = lib.mkIf config.services.stonenet.enable {
              environment = {
                etc."stonenet/config.toml".source = userConfigFile;

                systemPackages = lib.mkIf config.services.stonenet.desktop.enable [
                  #stonenet-desktop
                ];
              };

              systemd.services.stonenet = {
                description = "Stonenet Daemon";
                after = ["network-online.target"];
                wantedBy = ["multi-user.target"];

                serviceConfig = {
                  ExecStart = "${stonenet}/bin/stonenetd";
                  Type = "simple";

                  Restart = "on-failure";
                  StandardError = "journal+console";
                  StandardOutput = "journal+console";
                  WorkingDirectory = "${stonenet.share}";
                };
              };

              system.activationScripts.stonenet-state.text = ''
                set -e
                mkdir -p /var/lib/stonenet
                touch "${effectiveConfig.database_path}"
              '';
            };
          };

        packages.default = stonenet;
      });
}
