package main

import (
	"context"
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

func reportIssues() []*gorram.Issue {
	issue1 := &gorram.Issue{
		Message:       "woooo",
		TimeSubmitted: time.Now().Unix(),
	}
	issue2 := &gorram.Issue{
		Message:       "woooo1",
		TimeSubmitted: time.Now().Unix(),
	}
	issue3 := &gorram.Issue{
		Message:       "woooo2",
		TimeSubmitted: time.Now().Unix(),
	}
	return []*gorram.Issue{issue1, issue2, issue3}
}

func main() {
	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Set up a connection to the server.
	conn, err := grpc.Dial("127.0.0.1:50000", grpc.WithInsecure())
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

	// Ping and collect issues every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
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

				i := reportIssues()
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
