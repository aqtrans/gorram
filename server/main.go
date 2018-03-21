package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"jba.io/go/gorram/proto"
)

type gorramServer struct {
}

func (s *gorramServer) Ping(ctx context.Context, msg *gorram.PingMessage) (*gorram.PingMessage, error) {
	var client string

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		client = md["client"][0]
	}
	log.Println(client, "is", msg.IsAlive)
	return msg, nil
}

func (s *gorramServer) RecordIssue(ctx context.Context, issue *gorram.Issue) (*gorram.Submitted, error) {
	var client string

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		client = md["client"][0]
	}
	log.Println(client, "sent", issue.Message, time.Unix(issue.TimeSubmitted, 0))

	return &gorram.Submitted{SuccessfullySubmitted: true}, nil
}

func main() {
	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Setup the TCP port to listen on
	lis, err := net.Listen("tcp", "127.0.0.1:50000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("Listening on 127.0.0.1:50000")

	server := grpc.NewServer()

	gs := gorramServer{}

	gorram.RegisterReporterServer(server, &gs)

	// Start listening, in a goroutine so SIGINTs can be caught below
	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Listen for Ctrl+C
	go func() {
		sig := <-sigs
		log.Println(sig)
		done <- true
	}()

	<-done
	log.Println("Server exiting...")
	server.GracefulStop()

}
