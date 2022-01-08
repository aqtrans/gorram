# Gorram 
*So you know when the primary buffer panel falls off your gorram ship*

Written in Go. This is my attempt at a creating a monitoring system, similar to Sensu or Nagios. 

Inspired by Telegraf, a single-binary metrics agent, the goal is to have no external dependencies or process forking unless absolutely necessary. 
A vast majority of the current checks are implemented using the same library as Telegraf, [gopsutil](github.com/shirou/gopsutil). 

The server holds all configuration information in a YAML file on a per-client basis, and that client config is pushed to the client upon connect. 
[fsnotify](https://github.com/fsnotify/fsnotify) is used to watch and reload and send the config to the client as necessary, as part of the ping/heartbeat. 

Formerly using gRPC, I've recently moved to using [Twirp](https://github.com/twitchtv/twirp). Replacing Mutual TLS authentication with ed25519 signature verification. Each client has a private key specified in their `client.yml`, with their public key in the server's `conf.d/$clientname.yml`. On client connection, the shared secret is signed and sent to the server, to be verified against that client's public key. 

## Quickstart:  
- Fetch the package itself: `go get git.jba.io/go/gorram`  
- Or clone from git: `git clone https://git.jba.io/go/gorram`  
- Build: `./build.sh build`  
- Move/edit `client.yml.dist`, `clientname.yml.dist`, and `server.yml.dist` as necessary: 
    - `server.yml` is stored on the server-side
    - `client.yml` is stored on the client-side 
    - `$client_name.yml` files are stored in a `conf.d` directory on the server-side
        - One yml file per-client, with the filename matching the literal `$client_name` 
    - `secret_key` in `client.yml` and `server.yml` must match, it is the shared secret signed and verified
- Generate public/private keys for the client: `./gorram-client -generate-keys`
    - Place the private key into `client.yml` as `private_key` on the client-side
    - Place the public key into `conf.d/$client_name.yml` as `public_key` on the server-side

After 60 seconds, the checks should start flowing, checking anything specified in `$client_name.yml` on the client. 

## Config files:
- `client.yml.dist` is an example of the client-side configuration file
- `clientname.yml.dist` is an example of a server-side, client-specific configuration file, storing all the checks for the client
- `server.yml.dist` is an example of the server-side configuration file

## Currently implemented checks:
- Deluge: max number of torrents in an error, checking, or downloading state.  
- Disk Space: max percentage of disk space used on multiple mounts.  
- Load Average: max load average.  
- Process Existence: check that a given process is running, full path to the binary.  
- HTTP GET: checks that a specified URL returns a 200, and optionally, checks that the response body matches a given string.  
- Memory Usage: check percentage of used memory
- Postgres Replication: query the `pg_stat_replication` table on a Postgres master for a specific `client_addr`. 

Postgres check needs some aditional setup using `psql`:  
- To create user: `create user gorram with password '[reallySecurePassword]';`  
- To grant user permissions to monitor replication status: `grant pg_monitor to gorram;`  

## Alerts:  
Alerts will be sent if the number of identical alert occurences is 1, greater than 5, or the occurrences is evenly divisible by 10.  
This is a very rudimentary 'backoff' implementation. 

## Todo:  
- [x] Add additional alerting mechanisms (Pushover, email, etc). 
    - Currently [Pushover](https://pushover.net/) push notifications and log are implemented. 
- [ ] Add client expiration/deletion.  
    - Right now if a client disappears, the server will start alerting and never stop until the client re-appears. 
- [ ] Related to the above, implement some kind of frontend to interact with the server; manually delete clients, reload config, etc.  
    - CLI is in the works, but still working on the gRPC server endpoints
    - Basic web UI has been implemented, currently used to list and mute alerts
