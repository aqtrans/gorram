# Gorram - a simple monitoring system written in Golang

*So you know when the primary buffer panel falls off your gorram ship*

This is my attempt at a creating a monitoring system, similar to Sensu or Nagios. 

Inspired by Telegraf, a single-binary metrics agent, the goal is to have no external dependencies or process forking unless absolutely necessary.

gRPC is used for the client-server communication, protected by TLS and a password. TLS communication can be bypassed using the `-insecure` flag on both the client and server.  

The required TLS certificate can be generated by the server on-demand, using the `-generate-certs` and `-tls-host` flags, like so:  `./server -generate-certs -tls-host=192.168.0.1`. This generates `cert.pem` and `cert.key` in the working directory, and the cert.pem should be copied to the clients. This certificate is not used for any kind of HTTP communication, so being signed by a CA or setup via LetsEncrypt should not be necessary.

A very basic heartbeat is implemented, with the server waiting for a ping from the client every $Interval seconds, right after connect. If the ping is not received, the timer expires and a ticker fires off that alerts every $Interval+10 seconds until the client re-connects.  

The server holds all configuration information in a TOML file on a per-client basis, and that client config is pushed to the client upon connect. [fsnotify](https://github.com/fsnotify/fsnotify) is used to watch and reload and send the config to the client as necessary, as part of the ping/heartbeat. The client only needs to be pointed at the server with it's TLS certificate and secret key in hand.  

## Config file:
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

## Todo:  
- [ ] Add additional alerting mechanisms (Pushover, email, etc). 
    - Only logs right now.  
- [ ] Add client expiration/deletion.  
    - Right now if a client disappears, the server will start alerting and never stop until the client re-appears. 
    - Might implement some hold-off mechanism so the alerts get longer and longer apart, but still allow a manual deletion.
- [ ] Related to the above, implement some kind of frontend to interact with the server; manually delete clients, reload config, etc.  
    - Thinking of either a web UI or CLI