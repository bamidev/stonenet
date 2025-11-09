{
  description = "Stonenet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    browser-window.url = "github:bamidev/browser-window";
  };
  outputs = { nixpkgs, flake-utils, browser-window, ... }:
    flake-utils.lib.eachSystem flake-utils.lib.allSystems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        stdenv = pkgs.stdenv;
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
        desktopManifest = (pkgs.lib.importTOML ./desktop/Cargo.toml).package;
        workspaceCargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "ed448-rust-0.1.1" = "sha256-AnC3lAIJjnQ6VlZXpjVG/qpPBEIgbJS1/p4200XKCkc=";
          };
        };


        stonenet = pkgs.rustPlatform.buildRustPackage {
          pname = manifest.name;
          version = manifest.version;
          outputs = ["out" "share"];
          cargoLock = workspaceCargoLock;
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

        stonenetDesktop = pkgs.rustPlatform.buildRustPackage {
          pname = desktopManifest.name;
          version = desktopManifest.version;
          cargoLock = workspaceCargoLock;
          buildAndTestSubdir = "desktop";
          src = pkgs.lib.cleanSource ./.;

          # FIXME: Not sure why this isn't working:
          #nativeBuildInputs = browser-window.packages.${system}.webkitgtk.nativeBuildInputs;
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustPlatform.bindgenHook
          ];
          buildInputs = browser-window.packages.${system}.webkitgtk.buildInputs;
        };

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
        apps = {
          default = {
            name = "stonenet";
            type = "app";
            program = "${stonenet}/bin/stonenetd";
          };
          desktop = {
            name = "stonenet-desktop";
            type = "app";
            program = "${stonenetDesktop}/bin/stonenet-desktop";
          };
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
                  stonenetDesktop
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

        packages = {
          default = stonenet;
          desktop = stonenetDesktop;
        };
      });
}
