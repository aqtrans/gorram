package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"jba.io/go/gorram/checks"
	"jba.io/go/gorram/proto"
)

// This is where all the actual checks are done, and an array of "issues" is made
func doChecks(cfg *gorram.Config) []*gorram.Issue {
	var issues []*gorram.Issue

	// Check loadavg
	if cfg.Load != nil {
		issues = checks.GetCheck(issues, checks.LoadAvg{Cfg: *cfg.Load})
	}
	// Check disk usage, looping through given list of disks
	if cfg.Disk != nil {
		for _, diskCheck := range cfg.Disk {
			issues = checks.GetCheck(issues, checks.DiskSpace{Cfg: *diskCheck})
		}

	}
	// Check Deluge
	if cfg.Deluge != nil {
		issues = checks.GetCheck(issues, checks.DelugeCheck{Cfg: *cfg.Deluge})
	}
	// Check ps faux, looping through given list of full process names
	if cfg.Ps != nil {
		for _, psCheck := range cfg.Ps {
			issues = checks.GetCheck(issues, checks.ProcessExists{Cfg: *psCheck})
		}
	}
	// Check GET URLs, looping throug list of given URLs
	if cfg.GetUrl != nil {
		for _, urlCheck := range cfg.GetUrl {
			issues = checks.GetCheck(issues, checks.GetURL{Cfg: *urlCheck})
		}
	}

	return issues
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

func main() {
	// Set config via flags
	clientName := flag.String("name", "unnamed", "Name of the client, as seen by the server. Should be unique.")
	serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	insecure := flag.Bool("insecure", false, "Connect to server without TLS.")
	serverCert := flag.String("cert", "cert.pem", "Path to the certificate from the server.")
	secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")

	flag.Parse()

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	if *insecure {
		conn, err = grpc.Dial(*serverAddress, grpc.WithBlock(), grpc.WithInsecure(), grpc.WithPerRPCCredentials(&secret{
			Secret: *secretKey,
			TLS:    false,
		}))
	} else {
		creds, err = credentials.NewClientTLSFromFile(*serverCert, "")
		if err != nil {
			log.Fatal("Error parsing TLS cert:", err)
		}
		conn, err = grpc.Dial(*serverAddress, grpc.WithBlock(), grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(&secret{
			Secret: *secretKey,
			TLS:    true,
		}))
	}
	if err != nil {
		log.Printf("Error connecting to server: %v", err)
	}

	defer conn.Close()

	c := gorram.NewReporterClient(conn)

	// Add client name metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "client", *clientName)

	// Add secret key metadata
	//ctx = metadata.AppendToOutgoingContext(ctx, "secret", *secretKey)

	// Get config from server
	cfg, err := c.SendConfig(ctx, &gorram.ConfigRequest{
		ClientName: *clientName,
	})
	if err != nil {
		log.Fatalln(err)
	}

	//log.Println(cfg.LastUpdated)

	log.Println("Interval:", cfg.Interval)

	// Ping and collect issues every X seconds
	ticker := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:

				newCfg, err := c.Ping(ctx, &gorram.IsAlive{IsAlive: true, LastUpdated: cfg.LastUpdated})
				if err != nil {
					log.Fatalln(err)
				}
				if newCfg.String() != "" {
					log.Println("Loading new config from server...")
					cfg = newCfg
				}

				// Do checks
				i := doChecks(cfg)
				// If there are any checks, open a client-side stream and record them
				if len(i) > 0 {
					issueStream, err := c.RecordIssue(ctx)
					if err != nil {
						log.Fatalln(err)
					}

					for _, issue := range i {
						if err := issueStream.Send(issue); err != nil {
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
