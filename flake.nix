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
            "browser-window-0.12.3" = "sha256-a7RhMBnay7s7YATt1w1xFINGyZE6m3AuZQi4gOJokV4=";
          };
        };

        stonenet = {useHomeManager}: pkgs.rustPlatform.buildRustPackage {
          pname = manifest.name;
          version = manifest.version;
          outputs = ["out" "share"];
          cargoLock = workspaceCargoLock;
          src = pkgs.lib.cleanSource ./.;
          doCheck = false;
          buildFeatures = [
            "unbundled"
            (if !useHomeManager then "nixos" else "home-manager")
          ];

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

      in {
        apps = {
          default = {
            name = "stonenet";
            type = "app";
            program = "${stonenet {useHomeManager = false;}}/bin/stonenetd";
          };
          desktop = {
            name = "stonenet-desktop";
            type = "app";
            program = "${stonenetDesktop}/bin/stonenet-desktop";
          };
        };

        devShells = rec {
          default = openssl;
          openssl = pkgs.mkShell {
            packages = with pkgs; [ pkg-config pkgs.openssl.dev ];
          };
        };

        nixosModules = let
          options = { lib }: {
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

          moduleConfig = { config, lib, pkgs, useHomeManager }:
            let
              settingsFormat = pkgs.formats.toml {};
              defaultConfig = if !useHomeManager then
                (pkgs.lib.importTOML ./conf/default-system.toml)
              else
                (pkgs.lib.importTOML ./conf/default-user.toml);
              effectiveConfig = defaultConfig // config.services.stonenet.config;
              userConfigFile = settingsFormat.generate "stonenet.toml" effectiveConfig;
              stonenetPackage = stonenet { useHomeManager=useHomeManager; };

              systemdServiceConfig = {
                ExecStart = "${stonenetPackage}/bin/stonenetd";
                Type = "simple";

                Restart = "on-failure";
                StandardError = "journal+console";
                StandardOutput = "journal+console";
                # A workaround: stonenet looks for the templates and static files in the working directory at the moment
                WorkingDirectory = "${stonenetPackage.share}";
              };


            in lib.mkIf (config.services.stonenet.enable) (
              if !useHomeManager then {
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

                  serviceConfig = systemdServiceConfig;
                };

                system.activationScripts.stonenet-state.text = ''
                  set -e
                  mkdir -p /var/lib/stonenet
                  touch "${effectiveConfig.database_path}"
                '';
              } else {
                home = {
                  file.".config/stonenet/config.toml".source = userConfigFile;

                  packages = lib.mkIf config.services.stonenet.desktop.enable [
                    stonenetDesktop
                  ];
                };

                systemd.user.services.stonenet = {
                  Unit = {
                    Description = "Stonenet Daemon";
                    After = "network-online.target";
                    WantedBy = "multi-user.target";
                  };

                  Service = systemdServiceConfig;
                };
              }
            );
          in {
            default = { config, lib, pkgs, ... }: {
              options = options { lib=lib; };
              config = moduleConfig { config=config; lib=lib; pkgs=pkgs; useHomeManager=false; };
            };

            homeManager = { config, lib, pkgs, ... }: {
              options = options { lib=lib; };
              config = moduleConfig { config=config; lib=lib; pkgs=pkgs; useHomeManager=true; };
            };
        };

        packages = {
          default = stonenet { useHomeManager = false; };
          desktop = stonenetDesktop;
        };
      });
}
