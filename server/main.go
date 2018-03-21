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
	"google.golang.org/grpc/stats"
	"jba.io/go/gorram/proto"
)

type statHandler struct {
	// TagRPC can attach some information to the given context.
	// The context used for the rest lifetime of the RPC will be derived from
	// the returned context.
	//TagRPC(context.Context, *stats.RPCTagInfo) context.Context
	// HandleRPC processes the RPC stats.
	//HandleRPC(context.Context, RPCStats)

	// TagConn can attach some information to the given context.
	// The returned context will be used for stats handling.
	// For conn stats handling, the context used in HandleConn for this
	// connection will be derived from the context returned.
	// For RPC stats handling,
	//  - On server side, the context used in HandleRPC for all RPCs on this
	// connection will be derived from the context returned.
	//  - On client side, the context is not derived from the context returned.
	//TagConn(context.Context, *ConnTagInfo) context.Context
	// HandleConn processes the Conn stats.
	//HandleConn(context.Context, ConnStats)
}

func (s *statHandler) TagRPC(ctx context.Context, tagInfo *stats.RPCTagInfo) context.Context {
	return ctx
}

func (s *statHandler) HandleRPC(ctx context.Context, rpcStats stats.RPCStats) {

}

func (s *statHandler) TagConn(ctx context.Context, tagInfo *stats.ConnTagInfo) context.Context {
	log.Println("Inbound connection from", tagInfo.RemoteAddr)
	return ctx
}
func (s *statHandler) HandleConn(ctx context.Context, connStats stats.ConnStats) {

}

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

	sh := statHandler{}

	server := grpc.NewServer(grpc.StatsHandler(&sh))

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
