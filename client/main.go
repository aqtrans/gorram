package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"jba.io/go/gorram/proto"
)

type config struct {
	loadavg float64
}

type check interface {
	doCheck(config) *gorram.Issue
}

func reportIssues(cfg *config) []*gorram.Issue {
	var issues []*gorram.Issue
	issue := loadavg{}.doCheck(cfg)
	if issue != nil {
		issues = append(issues, issue)
	}
	return issues
}

func main() {
	// Set config via flags
	serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")

	// These flags are issue-specific
	loadAvg := flag.Float64("load-avg", 8, "The load average above which to alert on.")

	flag.Parse()

	cfg := &config{
		loadavg: *loadAvg,
	}

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Set up a connection to the server.
	conn, err := grpc.Dial(*serverAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := gorram.NewReporterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Add client name metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "client", "client1")

	// Add secret key metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "secret", *secretKey)

	// Ping and collect issues every X seconds
	ticker := time.NewTicker(*interval)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				ping, err := c.Ping(ctx, &gorram.PingMessage{IsAlive: true})
				if err != nil {
					log.Fatalln(err)
				}
				log.Println(ping.GetIsAlive())

				i := reportIssues(cfg)
				for _, issue := range i {
					submitted, err := c.RecordIssue(ctx, issue)
					if err != nil && err != io.EOF {
						log.Fatalln("omg", err)
					}

					log.Println(issue.Message, submitted)
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
