{ config, lib, pkgs, ... }:

with lib;

let 
  cfg = config.services.gorram;
  #gorram_client = config.services.gorram.client;
  #gorram_server = config.services.gorram.server;
  #cfg.client = config.services.gorram.client;
  #cfg.server = config.services.gorram.server;
  pkgDesc = "A simple Gorram monitoring system. Inspired by Telegraf, using the same system monitoring library.";

  serverConfFile = pkgs.writeText "server.yml" ''  
    secret_key: "${cfg.secretKey}"
    alert_method: "${cfg.alertMethod}" 
    pushover.app_key: "${cfg.pushoverAppKey}"
    pushover.user_key: "${cfg.pushoverUserKey}" 
    pushover.device: "${cfg.pushoverDevice}"    
    listen_address: "${cfg.listenAddress}"
    tls_host: "${cfg.tlsHostname}"
    heartbeat_seconds: ${cfg.heartbeatSeconds}
    debug: ${boolToString cfg.debug}
    domain: ${cfg.httpDomain}
  '';

  #clientCfg = config.services.gorram.client;
  #serverCfg = config.services.gorram.server;

  clientConfFile = pkgs.writeText "client.yml" ''  
    name: "${cfg.clientName}"
    secret_key: "${cfg.secretKey}" 
    server_address: "${cfg.serverAddress}"
  '';  

/* TODO: Figure out some way to generate individual conf.d/$client.yml files. Currently needs to be done manually
  clients = pkgs.writeText "conf.d/${clients.name}.yml" ''
    omg = "${clients.name.required}"
  '';
*/

in {

  options = {
    services.gorram = {

      serverEnable = mkEnableOption "${pkgName}.server";

        user = mkOption {
          type = types.str;
          default = "gorram";
          description = "gorram user";
        };

        group = mkOption {
          type = types.str;
          default = "gorram";
          description = "gorram group";
        };

        stateDir = mkOption {
          type = types.path;
          default = "/var/lib/gorram/";
          description = "state directory for gorram";
          example = "/home/user/.gorram/";
        };

        tlsDir = mkOption {
          type = types.str;
          default = "/var/lib/gorram/";
          description = "where to store the TLS certificates";
          example = "/home/user/.gorram/";
        };    

        listenAddress = mkOption {
          type = types.str;
          default = "0.0.0.0:50000";
          description = "Listen address, IP and port";
        };         

        secretKey = mkOption {
          type = types.str;
          default = "";
          description = "Secret key shared between clients and servers";
        };

        alertMethod = mkOption {
          type = types.str;
          default = "log";
          description = "How to alert. Currently either 'pushover' or 'log'";
        };      

        pushoverAppKey = mkOption {
          type = types.str;
          default = "";
          description = "App key for Pushover";
        };      

        pushoverUserKey = mkOption {
          type = types.str;
          default = "";
          description = "User key for Pushover";
        };              

        pushoverDevice = mkOption {
          type = types.str;
          default = "";
          description = "Device to notify via Pushover";
        };      

        tlsHostname = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "What hostname to generate the TLS certificate against";
        };  

        heartbeatSeconds = mkOption {
          type = types.str;
          default = "";
          description = "How often to sync with all clients";
        }; 

        debug = mkOption {
          type = types.bool;
          default = true;
          description = "Enable debug mode";
        }; 

        httpDomain = mkOption {
          type = types.str;
          default = "127.0.0.1";
          description = "What domain to listen for HTTP on";
        }; 

        clientEnable = mkEnableOption "${pkgName}.client";

        clientName = mkOption {
          type = types.str;
          default = "";
          description = "Name of the client to report back to the server";
        };   

        serverAddress = mkOption {
          type = types.str;
          default = "0.0.0.0:50000";
          description = "Server address, IP and port";
        };

    };
  };

  config = mkIf (cfg.serverEnable || cfg.clientEnable) {

        users.users.${cfg.user} = {
          name = cfg.user;
          group = cfg.group;
          home = cfg.stateDir;
          isSystemUser = true;
          createHome = true;
          description = pkgDesc;
        };

        users.groups.${cfg.user} = {
          name = cfg.group;
        };

        systemd.services.gorram_server = {
          description = pkgDesc;
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          serviceConfig = {
            User = cfg.user;
            Group = cfg.group;
            Restart = "always";
            ProtectSystem = "strict";
            ReadWritePaths = ''${serverConfFile} ${cfg.stateDir} ${cfg.tlsDir}'';
            WorkingDirectory = cfg.stateDir;
            ExecStart = ''
              ${pkgs.gorram}/bin/server -ssl-path ${cfg.tlsDir} -conf ${cfg.stateDir} -conf-file ${serverConfFile}
            '';
          };
        };

        systemd.services.gorram_client = {
          description = pkgDesc;
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          serviceConfig = {
            User = cfg.user;
            Group = cfg.group;
            Restart = "always";
            ProtectSystem = "strict";
            ReadWritePaths = ''${clientConfFile} ${cfg.tlsDir}'';
            WorkingDirectory = cfg.tlsDir;
            ExecStart = ''
              ${pkgs.gorram}/bin/client -ssl-path ${cfg.tlsDir} -conf ${clientConfFile}
            '';
          };
        };

  };

}
