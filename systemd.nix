{ config, lib, ... }: let
  stonenetPackage = (builtins.getFlake "github:bamidev/stonenet/dev").packages.${builtins.currentSystem}.default;
in {
  options = {
    services.stonenet = {
      enable = lib.mkEnableOption "stonenet";
      package = lib.mkOption {
        description = "Stonenet package to use";
        type = lib.types.package;
        default = stonenetPackage;
      };
    };
  };
  config = lib.mkIf config.services.stonenet.enable {
    systemd.services.stonenet = {
      serviceConfig = {
        ExecStart = "${stonenetPackage}/bin/stonenetd";
        Type = "simple";

        Restart = "on-failure";
        StandardOutput = "journal+console";
      };
      wantedBy = [ "multi-user.target" ];
    };
  };
}
