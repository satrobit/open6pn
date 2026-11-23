{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.open6pn;
  inherit (lib) mkOption types;
  hostMark = "0x6f36706f";

  flag = name: value: lib.optionals (value != null) [ "--${name}=${toString value}" ];
  args = lib.concatLists [
    [ "--etcd=${lib.concatStringsSep "," cfg.etcd.endpoints}" ]
    (flag "etcd-prefix" cfg.etcd.prefix)
    (flag "etcd-ca" cfg.etcd.caFile)
    (flag "etcd-cert" cfg.etcd.certFile)
    (flag "etcd-key" cfg.etcd.keyFile)
    (flag "advertise" cfg.advertise)
    (flag "wg-port" cfg.wireguardPort)
    (flag "mtu" cfg.mtu)
    (flag "node-bits" cfg.nodeBits)
    (flag "name" cfg.name)
    (flag "dns-domain" cfg.dns.domain)
    (flag "dns-upstream" (
      if cfg.dns.upstreams == [ ] then null else lib.concatStringsSep "," cfg.dns.upstreams
    ))
    [ "--socket=${cfg.socket}" ]
    cfg.extraArgs
  ];
in
{
  options.services.open6pn = {
    enable = lib.mkEnableOption "the open6pn private-network daemon";

    package = mkOption {
      type = types.package;
      description = "The open6pn package.";
    };

    etcd = {
      endpoints = mkOption {
        type = types.nonEmptyListOf types.str;
        example = [ "https://etcd-1:2379" ];
        description = "etcd endpoints every host of the mesh can reach.";
      };
      prefix = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Key prefix in etcd; one prefix is one mesh. Null keeps the daemon's default.";
      };
      caFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "CA certificate for etcd, as a path read at runtime.";
      };
      certFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Client certificate for etcd, as a path read at runtime.";
      };
      keyFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Client key for etcd, as a path read at runtime. Keep it out of the Nix store.";
      };
      userFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "File holding OPEN6PN_ETCD_USER=user:password, loaded as an environment file.";
      };
    };

    advertise = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Address other hosts reach this host on. Null uses the default route's source address.";
    };

    wireguardPort = mkOption {
      type = types.port;
      default = 51820;
      description = "WireGuard UDP port.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = "Open the WireGuard port in the NixOS firewall.";
    };

    mtu = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = "First host of a cluster only: the WireGuard MTU. Fixed once the cluster exists.";
    };

    nodeBits = mkOption {
      type = types.nullOr (types.ints.between 8 16);
      default = null;
      description = "First host of a cluster only: IPv4 bits that number the host. Fixed once the cluster exists.";
    };

    name = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Node name. Null uses the hostname.";
    };

    dns = {
      domain = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Domain endpoint names are served under. Null keeps the daemon's default (internal).";
      };
      upstreams = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Resolvers for other names. Empty uses the host's /etc/resolv.conf.";
      };
    };

    socket = mkOption {
      type = types.str;
      default = "/run/open6pn.sock";
      description = "Path of the daemon's control socket, readable by root only.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Further flags for `open6pn daemon`.";
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernelModules = [ "wireguard" ] ++ lib.optional (!config.networking.nftables.enable) "xt_mark";

    environment.systemPackages = [ cfg.package ];
    environment.variables.OPEN6PN_SOCKET = cfg.socket;

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.wireguardPort ];
    networking.firewall.extraInputRules = lib.mkIf config.networking.nftables.enable "meta mark ${hostMark} accept";
    networking.firewall.extraCommands = lib.mkIf (
      !config.networking.nftables.enable
    ) "ip6tables -I nixos-fw -m mark --mark ${hostMark} -j nixos-fw-accept";

    networking.dhcpcd.denyInterfaces = [
      "o6pn*"
      "open6pn-wg"
    ];

    systemd.services.open6pn = {
      description = "open6pn private-network daemon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe cfg.package)
            "daemon"
          ]
          ++ args
        );
        EnvironmentFile = lib.mkIf (cfg.etcd.userFile != null) cfg.etcd.userFile;
        StateDirectory = "open6pn";
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = 2;
      };
    };
  };
}
