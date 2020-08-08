# Gorram 
*So you know when the primary buffer panel falls off your gorram ship*

Written in Go. This is my attempt at a creating a monitoring system, similar to Sensu or Nagios. 

Inspired by Telegraf, a single-binary metrics agent, the goal is to have no external dependencies or process forking unless absolutely necessary. 
A vast majority of the current checks are implemented using the same library as Telegraf, [gopsutil](github.com/shirou/gopsutil).

gRPC is used for the client-server communication, protected by Mutual TLS and a shared secret. TLS communication can be bypassed using the `-insecure` flag on both the client and server.  

Mutual TLS is used either via pre-generated (likely self-signed) CA, server, and client certificates ([gorram-certs](git.jba.io/go/gorram/certs/gorram-certs) can assist with this), or optionally the server and clients can generate dynamic certificates on startup, using a common CA certificate and key.

Without certificates in place, the server will generate and save a CA certificate and key, and generate a server certificate in memory using that CA.
Copy that generated CA certificate and key to the client in order to allow the client to dynamically generate a client certificate. 

A very basic heartbeat is implemented, with the server waiting for a ping from the client every `$interval` seconds, right after connect. 
If the ping is not received, the timer expires and a ticker fires off that alerts every `$interval`*2 seconds until the client re-connects.  

The server holds all configuration information in a YAML file on a per-client basis, and that client config is pushed to the client upon connect. 
[fsnotify](https://github.com/fsnotify/fsnotify) is used to watch and reload and send the config to the client as necessary, as part of the ping/heartbeat. 

The client only needs to be pointed at the server with either it's own TLS certificate and secret key, or a common CA certificate and key in hand, greatly simplifying management of the checks. 

## Quickstart:  
- Fetch the package itself: `go get git.jba.io/go/gorram`  
- Or clone from git: `git clone https://git.jba.io/go/gorram`  
- Build: `./build.sh build`  
- Move/edit `client.yml.dist`, `clientname.yml.dist`, and `server.yml.dist` as necessary: 
    - `server.yml` is stored on the server-side
    - `client.yml` is stored on the client-side 
    - `clientname.yml` files are stored in a `conf.d` directory on the server-side
        - One yml file per-client, with the filename matching the `clientname` 
    - `secret_key` in `client.yml` and `server.yml` must match
    - `tls_host` in `server.yml` must be edited as necessary to allow TLS certificate generation
        - You can set it to an IP
- Startup the server: `./gorram-server -generate-ca -debug -conf ./ -ssl-path ./`
    - With `-generate-ca`, a CA key and certificate will be generated to `ssl-path` on startup, so if the client and server are running on different machines
        for this quickstart, you must copy them to the client's `ssl-path`
- Startup the client: `./gorram-client -debug -conf ./client.yml -ssl-path ./`

After 60 seconds, the checks should start flowing, checking anything specified in `clientname.yml` on the client. 

## Mutual TLS with pre-generated certificates:
Generating your own certificates ahead of time, using `gorram-certs`:
- `go get git.jba.io/go/gorram/certs/gorram-certs`
- Generate a CA: `gorram-certs -ca`
- Generate a server cert: `gorram-certs -host "IP or hostname of server" -server`
- Generate a client cert: `gorram-certs -host "client name" -client`

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
