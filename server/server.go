package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"jba.io/go/gorram/gorram"
)

type gorramServer struct {
}

func (s *gorramServer) Ping(ctx context.Context, msg *gorram.PingMessage) (*gorram.PingMessage, error) {
	log.Println(msg.ClientName, ":", msg.IsAlive)
	return msg, nil
}

func (s *gorramServer) RecordIssue(reporter gorram.Reporter_RecordIssueServer) error {
	i, err := reporter.Recv()
	if err != nil {
		log.Println(err)
	}
	err = reporter.SendAndClose(&gorram.Submitted{SuccessfullySubmitted: true})
	if err != nil {
		log.Println(err)
	}
	log.Println(i.ClientName, i.Message, i.TimeSubmitted)
	return nil
}

func main() {
	lis, err := net.Listen("tcp", "127.0.0.1:50000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("Listening on 127.0.0.1:50000")
	server := grpc.NewServer()

	gs := gorramServer{}

	gorram.RegisterReporterServer(server, &gs)

	if err := server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
