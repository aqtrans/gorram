package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"jba.io/go/gorram/proto"
)

type config struct {
	secretKey string
}

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
	pingTimers    sync.Map
	clientList    sync.Map
	clientTickers sync.Map
	/*
		pingTimers    map[string]*time.Timer
		clientList    map[string]chan bool
		clientTickers map[string]*time.Ticker
	*/
}

func getClientName(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		return md["client"][0]
	}
	return "no-client-name"
}

func (s *gorramServer) Ping(ctx context.Context, msg *gorram.PingMessage) (*gorram.PingMessage, error) {
	// Variables to eventually change into config values:
	tickerInterval := 5
	pingInterval := 10

	client := getClientName(ctx)
	// This might be redundant since this should always be true
	if msg.IsAlive {
		log.Println(client, "is alive!")
	}

	// Setup a ping timer
	clientTimer, ok := s.pingTimers.Load(client)

	if ok {
		log.Println("Timer found, adding", pingInterval, "seconds.")
		clientTimer.(*time.Timer).Reset(time.Duration(pingInterval) * time.Second)

	} else {
		log.Println("Creating new timer for", pingInterval, "seconds")
		if ticker, ok := s.clientTickers.Load(client); ok {
			log.Println("Found an existing ticker for client, stopping and deleting it")
			ticker.(*time.Ticker).Stop()
			s.clientTickers.Delete(client)
		}

		s.pingTimers.Store(client, time.AfterFunc(time.Duration(tickerInterval)*time.Second, func() {
			// Delete the timer
			s.pingTimers.Delete(client)
			// Create a ticker to notify about disconnected clients
			s.clientTickers.Store(client, time.NewTicker(5*time.Second))
			ticker, ok := s.clientTickers.Load(client)
			if ok {
				for t := range ticker.(*time.Ticker).C {
					log.Println(client, "PINGS NOT RECEIVED IN 10 SECONDS", t)
				}
			}
		}))
	}

	log.Println("Number of goroutines:", runtime.NumGoroutine())

	return msg, nil
}

func pingWait(client string, timer *time.Timer, reset chan bool) {
	pingRecvd := <-reset
	// If a ping was received, reset the timer
	if pingRecvd {
		stop := timer.Reset(time.Second * 10)
		if !stop {
			log.Println("Error stopping pingTimer")
		}
	}
	<-timer.C
}

func (s *gorramServer) RecordIssue(ctx context.Context, issue *gorram.Issue) (*gorram.Submitted, error) {
	log.Println(getClientName(ctx), "sent", issue.Message, time.Unix(issue.TimeSubmitted, 0))

	return &gorram.Submitted{SuccessfullySubmitted: true}, nil
}

func (cfg config) authorize(ctx context.Context) error {

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if len(md["secret"]) > 0 && md["secret"][0] == cfg.secretKey {
			return nil
		}
	}
	err := errors.New("Access Denied")
	log.Println(err)
	return err
}

func (cfg config) unaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := cfg.authorize(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func main() {

	// Set config via flags
	insecure := flag.Bool("insecure", false, "Disable TLS. Allow insecure client connections.")
	serverAddress := flag.String("listen-address", "127.0.0.1:50000", "Address and port to listen on.")
	serverCert := flag.String("cert", "cert.pem", "Path to the server certificate.")
	serverCertKey := flag.String("key", "cert.key", "Path to the server certificate key.")
	generate := flag.Bool("generate-certs", false, "Generate certs if given.")
	generateHost := flag.String("tls-host", "127.0.0.1", "If generate-certs is specified, override the host in the cert.")
	secret := flag.String("server-secret", "omg12345", "Secret key of the server.")
	flag.Parse()

	cfg := &config{
		secretKey: *secret,
	}

	// TLS stuff
	var creds credentials.TransportCredentials
	if *generate {
		log.Println("Generating certs to ./cert.pem and ./cert.key")
		generateCerts(*generateHost)
	}

	if !*insecure {
		var err error
		creds, err = credentials.NewServerTLSFromFile(*serverCert, *serverCertKey)
		if err != nil {
			log.Fatal("Error with certs:", err)
		}
	}

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Setup the TCP port to listen on
	lis, err := net.Listen("tcp", *serverAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("Listening on", *serverAddress)

	sh := statHandler{}

	var server *grpc.Server
	if *insecure {
		server = grpc.NewServer(grpc.StatsHandler(&sh), grpc.UnaryInterceptor(cfg.unaryInterceptor))
	} else {
		server = grpc.NewServer(grpc.Creds(creds), grpc.StatsHandler(&sh), grpc.UnaryInterceptor(cfg.unaryInterceptor))
	}

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

	// When Ctrl+C is caught, do this
	<-done
	log.Println("Server exiting...")
	server.GracefulStop()

}
