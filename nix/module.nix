self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.bommer;
  yaml = pkgs.formats.yaml { };
  configuration = yaml.generate "bommer.yaml" cfg.settings;
in {
  options.services.bommer = {
    enable = lib.mkEnableOption "Bommer collection service";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    };
    settings = lib.mkOption {
      type = yaml.type;
      default = {
        version = 1;
        output.directory = "/var/lib/bommer/results";
      };
      description = "Bommer configuration. Explicitly enable collectors; do not put secrets here (stored in the Nix store).";
    };
    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "External collectors and host utilities available to the service.";
    };
    schedule = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "daily";
      description = "Optional systemd calendar schedule. Null leaves collection manual.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.bommer = {
      description = "Collect configured bills of materials";
      path = cfg.extraPackages;
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        StateDirectory = "bommer";
        StateDirectoryMode = "0700";
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ExecStart = "${lib.getExe cfg.package} scan --config ${configuration}";
      };
    };
    systemd.timers.bommer = lib.mkIf (cfg.schedule != null) {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule;
        Persistent = true;
      };
    };
  };
}
