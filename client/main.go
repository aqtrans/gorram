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
	maxLoad float64
}

type checkData struct {
	issue *gorram.Issue
	ok    bool
}

type check interface {
	doCheck() *checkData
}

// This is where all the actual checks are done, and an array of "issues" are made
func doChecks(cfg *config) []*gorram.Issue {
	var checks []*gorram.Issue
	loadCheck := getCheck(loadavg{maxLoad: cfg.maxLoad})
	if loadCheck != nil {
		checks = append(checks, loadCheck)
	}
	return checks
}

// getCheck() is a function which all Checks should run through
// It should only be called above by doCheck(), which then checks if the issue is nil
func getCheck(c check) *gorram.Issue {
	//log.Println("Check:", c)
	theCheck := c.doCheck()
	if !theCheck.ok {
		log.Println("Check is not OK:", theCheck)
		return theCheck.issue
	}

	return nil
}

func main() {
	// Set config via flags
	serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")

	// These flags are issue-specific
	maxload := flag.Float64("load-avg", 8, "The load average above which to alert on.")

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
	conn, err := grpc.Dial(*serverAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := gorram.NewReporterClient(conn)

	// Add client name metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "client", "client1")

	// Add secret key metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "secret", *secretKey)

	cfg := &config{
		maxLoad: *maxload,
	}

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
				log.Println("ping is", ping.GetIsAlive())

				i := doChecks(cfg)
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
