# Gorram 
*So you know when the primary buffer panel falls off your gorram ship*

Written in Go. This is my attempt at a creating a monitoring system, similar to Sensu or Nagios. 

Inspired by Telegraf, a single-binary metrics agent, the goal is to have no external dependencies or process forking unless absolutely necessary. 
A vast majority of the current checks are implemented using the same library as Telegraf, [gopsutil](github.com/shirou/gopsutil).

gRPC is used for the client-server communication, protected by Mutual TLS and a password. TLS communication can be bypassed using the `-insecure` flag on both the client and server.  

Mutual TLS is used either via pre-generated (likely self-signed) CA, server, and client certificates ([gorram-certs](git.jba.io/go/gorram/certs/gorram-certs) can assist with this), or optionally the server and clients can generate dynamic certificates on startup, using a common CA certificate and key.

Without certificates in place, the server will generate and save a CA certificate and key, and generate a server certificate in memory using that CA.
Copy that generated CA certificate and key to the client in order to allow the client to dynamically generate a client certificate. 

A very basic heartbeat is implemented, with the server waiting for a ping from the client every `$interval` seconds, right after connect. 
If the ping is not received, the timer expires and a ticker fires off that alerts every `$interval`+10 seconds until the client re-connects.  

The server holds all configuration information in a TOML file on a per-client basis, and that client config is pushed to the client upon connect. 
[fsnotify](https://github.com/fsnotify/fsnotify) is used to watch and reload and send the config to the client as necessary, as part of the ping/heartbeat. 

The client only needs to be pointed at the server with either it's own TLS certificate and secret key, or a common CA certificate and key in hand, greatly simplifying management of the checks. 

## Mutual TLS with pre-generated certificates:
Generating your own certificates ahead of time, using `gorram-certs`:
- `go get git.jba.io/go/gorram/certs/gorram-certs`
- Generate a CA: `gorram-certs -ca`
- Generate a server cert: `gorram-certs -host "IP or hostname of server" -server`
- Generate a client cert: `gorram-certs -host "client name" -client`

## Config file example:
```
[clientName]
    Interval = 5

    [clientName.Deluge]
    URL = "http://127.0.0.1:8112/json"
    Password = "deluge"
    MaxTorrents = 5

    [[clientName.Disk]]
    Partition = "/"

    [[clientName.Disk]]
    Partition = "/media/USB"    
    MaxUsage = 10.0

    [[clientName.Ps]]
    FullPath = "/usr/lib/firefox/firefox"

    [clientName.Load]
    MaxLoad = 0.50

    [[clientName.GetUrl]]
    Url = "https://example.tld/health"
    # Quotes must be escaped, per TOML spec:
    ExpectedBody = "{\"alive\": true}"    
```  

## Currently implemented checks:
- Deluge: max number of torrents in an error, checking, or downloading state.  
- Disk Space: max percentage of disk space used on multiple mounts.  
- Load Average: max load average.  
- Process Existence: check that a given process is running, full path to the binary.  
- HTTP GET: checks that a specified URL returns a 200, and optionally, checks that the response body matches a given string.  
- Memory Usage: check percentage of used memory

## Quickstart:
Fetch the package itself: `go get git.jba.io/go/gorram`

Install dependencies, using [dep](https://github.com/golang/dep):  
- `go get -u github.com/golang/dep/cmd/dep` might be used to install it, but in my experience their HEAD is usually broken
- `cd ~/go/src/git.jba.io/go/gorram/server && ~/go/bin/dep ensure && go get -d`
- `cd ~/go/src/git.jba.io/go/gorram/checks && ~/go/bin/dep ensure && go get -d`
- `cd ~/go/src/git.jba.io/go/gorram/client && go get -d`
- `cd ~/go/src/git.jba.io/go/gorram/server`, copy/edit `config.dist.toml` as needed, noting the `SecretKey` and `ListenAddress`
- `cd ~/go/src/git.jba.io/go/gorram/client`, copy/edit `client.dist.toml` as needed, matching up the `ServerSecret` and `ServerAddress`

Generate SSL certs used to encrypt the traffic: `go run server/main.go server/generate_cert.go -conf ./config.toml -cert ./cert.pem -key ./cert.key -generate-certs`  
Start server: `go run server/main.go server/generate_cert.go -conf ./config.toml -cert ./cert.pem -key ./cert.key`  
Start client: `go run client/main.go -conf ./client.toml`  

If successful, you should see something similar to the following on the server-side, showing the client connecting and fetching it's config:
```
2019/03/24 21:34:01 Loaded config for a-client from config.toml...
2019/03/24 21:34:01 Loaded config for another-client from config.toml...
2019/03/24 21:34:01 Listening on 127.0.0.1:50000
2019/03/24 21:34:05 Inbound connection from 127.0.0.1:12345
2019/03/24 21:34:05 Connection has begun
2019/03/24 21:34:05 a-client has synced config.
```

## Todo:  
- [x] Add additional alerting mechanisms (Pushover, email, etc). 
    - Currently [Pushover](https://pushover.net/) push notifications and log are implemented. 
- [ ] Add client expiration/deletion.  
    - Right now if a client disappears, the server will start alerting and never stop until the client re-appears. 
    - Might implement some hold-off mechanism so the alerts get longer and longer apart, but still allow a manual deletion.
- [ ] Related to the above, implement some kind of frontend to interact with the server; manually delete clients, reload config, etc.  
    - CLI is in the works, but still working on the gRPC server endpoints
    - I'd then like to implement a chat bot based on those implemented endpoints