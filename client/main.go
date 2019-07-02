package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"google.golang.org/grpc/keepalive"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"git.jba.io/go/gorram/certs"
	"git.jba.io/go/gorram/checks"
	gorram "git.jba.io/go/gorram/proto"
	toml "github.com/pelletier/go-toml"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type clientConfig struct {
	ClientName    string
	ServerSecret  string
	ServerAddress string
}

type secret struct {
	Secret string
	TLS    bool
}

func (s *secret) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	//log.Println(uri, ctx)
	return map[string]string{
		"secret": s.Secret,
	}, nil
}

func (s *secret) RequireTransportSecurity() bool {
	return s.TLS
}

func loadConfig(confFile string) clientConfig {
	var cfg clientConfig
	// Load config.toml here
	cfgTree, err := toml.LoadFile(confFile)
	if err != nil {
		log.Fatalln("Error reading config.toml", err)
	}
	cfgTree.Unmarshal(&cfg)
	log.Println(cfg)
	return cfg
}

func main() {
	// Set config via flags
	confFile := flag.String("conf", "config.toml", "Path to the TOML config file.")
	//clientName := flag.String("name", "unnamed", "Name of the client, as seen by the server. Should be unique.")
	//serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	insecure := flag.Bool("insecure", false, "Connect to server without TLS.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the certificate from the server.")
	//secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")
	flag.Parse()

	// Set a global RPC timeout, to be used in context.WithTimeout()'s alongside each RPC call
	rpcTimeout := 10 * time.Second

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	tomlCfg := loadConfig(*confFile)

	/* Trying to send client-name as early as possible...
		Doesn't seem to send on the Dial
	// Metadata
	md := metadata.New(map[string]string{
		"client": "client1",
		"secret": *secretKey,
	})
	err := grpc.SetHeader(ctx, md)
	*/

	// Set up a connection to the server.
	var conn *grpc.ClientConn
	var err error
	var creds credentials.TransportCredentials

	kp := keepalive.ClientParameters{
		Time:                60 * time.Second,
		Timeout:             30 * time.Second,
		PermitWithoutStream: false,
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer dialCancel()
	if *insecure {
		conn, err = grpc.DialContext(
			dialCtx,
			tomlCfg.ServerAddress,
			grpc.WithInsecure(),
			grpc.WithPerRPCCredentials(&secret{
				Secret: tomlCfg.ServerSecret,
				TLS:    false,
			}),
			grpc.WithKeepaliveParams(kp),
		)
	} else {
		// If a certificate at $ClientName.pem exists, load it, otherwise generate one dynamically
		var tlsCert tls.Certificate
		certPath := tomlCfg.ClientName + ".pem"
		if _, err := os.Stat(certPath); err == nil {
			log.Println(certPath, "exists. Loading cert.")
			// Load static certs:
			tlsCert, err = tls.LoadX509KeyPair(tomlCfg.ClientName+".pem", tomlCfg.ClientName+".key")
			if err != nil {
				log.Fatalln("Error reading", tomlCfg.ClientName+".pem", err)
			}
		} else {
			log.Println("Generating certificate dynamically...")
			// Generate certificates dynamically:
			tlsCert = certs.GenerateClientCert(tomlCfg.ClientName, "cacert.pem", "cacert.key")
		}

		var host string
		host, _, err := net.SplitHostPort(tomlCfg.ServerAddress)
		if err != nil {
			log.Println("Error parsing ServerAddress from config; Watch out for TLS issues due to ServerName mismatch.", err)
			host = tomlCfg.ServerAddress
		}

		caCertRaw, err := ioutil.ReadFile("cacert.pem")
		if err != nil {
			log.Fatalln("Error reading", "cacert.pem", err)
		}
		certPool := x509.NewCertPool()
		if success := certPool.AppendCertsFromPEM(caCertRaw); !success {
			log.Fatalln("cannot append certs from PEM")
		}

		creds = credentials.NewTLS(&tls.Config{
			ServerName:   host, // NOTE: this is required!
			Certificates: []tls.Certificate{tlsCert},
			RootCAs:      certPool,
		})

		conn, err = grpc.DialContext(
			dialCtx,
			tomlCfg.ServerAddress,
			grpc.WithTransportCredentials(creds),
			grpc.WithPerRPCCredentials(&secret{
				Secret: tomlCfg.ServerSecret,
				TLS:    true,
			}),
			grpc.WithKeepaliveParams(kp),
		)
	}
	if err != nil {
		log.Printf("Error connecting to server: %v", err)
		return
	}

	defer conn.Close()

	c := gorram.NewReporterClient(conn)

	// Create RPC context, add client name metadata
	rpcCtx, rpcCancel := context.WithTimeout(context.Background(), rpcTimeout)
	rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "client", tomlCfg.ClientName)

	// Hello: Get config from server, and ensure dead tickers are stopped
	origCfg, err := c.Hello(rpcCtx, &gorram.ConfigRequest{
		ClientName: tomlCfg.ClientName,
	})
	if err != nil {
		log.Fatalln("Error with c.Hello:", err)
	}
	rpcCancel()

	//cfg := *origCfg

	log.Println("Interval:", origCfg.Interval)

	cfgMutex := &sync.Mutex{}

	// Ping and collect issues every X seconds
	ticker := time.NewTicker(time.Duration(origCfg.Interval) * time.Second)
	quit := make(chan struct{})
	cfgChan := make(chan *gorram.Config)

	go func() {
		for {
			select {
			case <-ticker.C:
				go func() {
					// Create RPC context, add client name metadata
					rpcCtx, rpcCancel := context.WithTimeout(context.Background(), rpcTimeout)
					rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "client", tomlCfg.ClientName)
					defer rpcCancel()

					cfgMutex.Lock()
					//log.Println("ping")
					pingResp, err := c.Ping(rpcCtx, &gorram.PingMsg{IsAlive: true, CfgLastUpdated: origCfg.LastUpdated})
					if err != nil {
						log.Fatalln("Error with c.Ping:", err)
					}
					// This variable should be true if the config is out of sync
					if pingResp.CfgOutOfSync {
						// Fetch and set the new config
						log.Println("Configuration out of sync. Fetching new config from server.")
						var err error
						// Create RPC context, add client name metadata
						rpcCtx, rpcCancel := context.WithTimeout(context.Background(), rpcTimeout)
						rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "client", tomlCfg.ClientName)
						defer rpcCancel()

						newCfg, err := c.ConfigSync(rpcCtx, &gorram.ConfigRequest{
							ClientName: tomlCfg.ClientName,
						})
						if err != nil {
							log.Fatalln("Error with c.ConfigSync:", err)
						}
						// Set cfg to newCfg
						//cfg = *newCfg
						origCfg = newCfg
						log.Println(origCfg.LastUpdated, newCfg.LastUpdated)
					}
					// Send config, either the new or old, through the channel
					cfgChan <- origCfg
					cfgMutex.Unlock()
					//close(cfgChan)
				}()
				go func() {
					// Create RPC context, add client name metadata
					rpcCtx, rpcCancel := context.WithTimeout(context.Background(), rpcTimeout)
					rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "client", tomlCfg.ClientName)
					defer rpcCancel()

					//log.Println("checks")
					cfg2 := <-cfgChan

					//log.Println("Enabled checks:", cfg.EnabledChecks)

					/*
						for _, v := range checks.TheChecks {
							log.Println(v.Title())
						}
					*/

					// Do checks
					i := checks.DoChecks(cfg2)
					// If there are any checks, open a client-side stream and record them
					if len(i) > 0 {
						issueStream, err := c.RecordIssue(rpcCtx)
						if err != nil {
							log.Fatalln("Error recording issue:", err)
						}

						for _, issue := range i {
							if err := issueStream.Send(&issue); err != nil {
								log.Fatalln("Error submitting issue:", err)
							}
						}
						reply, err := issueStream.CloseAndRecv()
						if err != nil {
							log.Fatalln("Error closing issueStream:", err)
						}
						if !reply.SuccessfullySubmitted {
							log.Fatalln("Error submitting issue; Check server logs.", reply.SuccessfullySubmitted)
						}
					}
				}()
				log.Println("Number of Goroutines:", runtime.NumGoroutine())
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	go func() {
		sig := <-sigs
		log.Println(sig)
		done <- true
	}()

	<-done
	log.Println("Client exiting...")
	ticker.Stop()
	err = conn.Close()
	if err != nil {
		log.Println("Error closing connection:", err)
	}

}
