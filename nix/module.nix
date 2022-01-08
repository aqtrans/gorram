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
    pushover
      app_key: "${cfg.pushoverAppKey}"
      user_key: "${cfg.pushoverUserKey}" 
      #device: "${cfg.pushoverDevice}"    
    listen_address: "${cfg.listenAddress}"
    heartbeat_seconds: ${cfg.heartbeatSeconds}
    debug: ${boolToString cfg.debug}
    domain: ${cfg.httpDomain}
    brancha_key: "${cfg.brancaKey}"
  '';

  #clientCfg = config.services.gorram.client;
  #serverCfg = config.services.gorram.server;

  clientConfFile = pkgs.writeText "client.yml" ''  
    name: "${cfg.clientName}"
    secret_key: "${cfg.secretKey}" 
    server_address: "${cfg.serverAddress}"
    private_key: "${cfg.clientPrivateKey}"
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

        brancaKey = mkOption {
          type = types.str;
          default = "";
          description = "A 32 character string used to generate session tokens.";
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

        clientPrivateKey = mkOption {
          type = types.str;
          default = "";
          description = "The client's base64-encoded private key";
        };        

/*
        clients = mkOption {
            description = "Gorram clients";
            type = with types; listOf (submodule {
              options = {
                name = mkOption {
                  type = str;
                };        
                foo = mkOption {
                  type = int;
                };
                bar = mkOption {
                  type = str;
                };
              };
            });
          }; 
*/         

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
            ReadWritePaths = ''${serverConfFile} ${cfg.stateDir}'';
            WorkingDirectory = cfg.stateDir;
            ExecStart = ''
              ${pkgs.gorram}/bin/server -conf ${cfg.stateDir} -conf-file ${serverConfFile}
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
            ReadWritePaths = ''${clientConfFile}'';
            ExecStart = ''
              ${pkgs.gorram}/bin/client -conf ${clientConfFile}
            '';
          };
        };

  };

}
