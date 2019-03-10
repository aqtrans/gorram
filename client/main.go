package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

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
	serverCert := flag.String("cert", "cert.pem", "Path to the certificate from the server.")
	//secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")
	flag.Parse()

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	if *insecure {
		conn, err = grpc.DialContext(dialCtx, tomlCfg.ServerAddress, grpc.WithBlock(), grpc.WithInsecure(), grpc.WithPerRPCCredentials(&secret{
			Secret: tomlCfg.ServerSecret,
			TLS:    false,
		}))
	} else {
		creds, err = credentials.NewClientTLSFromFile(*serverCert, "")
		if err != nil {
			log.Fatal("Error parsing TLS cert:", err)
		}
		conn, err = grpc.DialContext(dialCtx, tomlCfg.ServerAddress, grpc.WithBlock(), grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(&secret{
			Secret: tomlCfg.ServerSecret,
			TLS:    true,
		}))
	}
	if err != nil {
		log.Printf("Error connecting to server: %v", err)
		return
	}

	defer conn.Close()

	c := gorram.NewReporterClient(conn)

	// Add client name metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "client", tomlCfg.ClientName)

	// Add secret key metadata
	//ctx = metadata.AppendToOutgoingContext(ctx, "secret", *secretKey)

	// Hello: Get config from server, and ensure dead tickers are stopped
	cfg, err := c.Hello(ctx, &gorram.ConfigRequest{
		ClientName: tomlCfg.ClientName,
	})
	if err != nil {
		log.Fatalln("Error with c.Hello:", err)
	}

	log.Println("Interval:", cfg.Interval)

	// Ping and collect issues every X seconds
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	quit := make(chan struct{})
	cfgChan := make(chan *gorram.Config)

	go func() {
		for {
			select {
			case <-ticker.C:
				go func() {
					//log.Println("ping")
					pingResp, err := c.Ping(ctx, &gorram.PingMsg{IsAlive: true, CfgLastUpdated: cfg.LastUpdated})
					if err != nil {
						log.Fatalln("Error with c.Ping:", err)
					}
					// This variable should be true if the config is out of sync
					if pingResp.CfgOutOfSync {
						// Fetch and set the new config
						log.Println("Configuration out of sync. Fetching new config from server.")
						var err error
						newCfg, err := c.ConfigSync(ctx, &gorram.ConfigRequest{
							ClientName: tomlCfg.ClientName,
						})
						if err != nil {
							log.Fatalln("Error with c.ConfigSync:", err)
						}
						// Set cfg to newCfg
						cfg = newCfg
						log.Println(cfg.LastUpdated, newCfg.LastUpdated)
					}
					// Send config, either the new or old, through the channel
					cfgChan <- cfg
					//close(cfgChan)
				}()
				go func() {
					//log.Println("checks")
					cfg = <-cfgChan

					//log.Println("Enabled checks:", cfg.EnabledChecks)

					/*
						for _, v := range checks.TheChecks {
							log.Println(v.Title())
						}
					*/

					// Do checks
					i := checks.DoChecks(cfg)
					// If there are any checks, open a client-side stream and record them
					if len(i) > 0 {
						issueStream, err := c.RecordIssue(ctx)
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
	cancel()
	ticker.Stop()
	err = conn.Close()
	if err != nil {
		log.Println("Error closing connection:", err)
	}

}
