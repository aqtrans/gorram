package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pelletier/go-toml"

	"google.golang.org/grpc/credentials"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"jba.io/go/gorram/proto"
)

type config struct {
	secretKey   string
	alertMethod string
	configFile  string
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
	clientTimers
	clientCfg *sync.Map
	cfg       *config
	/*
		pingTimers    map[string]*time.Timer
		clientList    map[string]chan bool
		clientTickers map[string]*time.Ticker
	*/
}

type clientTimers struct {
	tickers sync.Map
	timers  sync.Map
}

func getClientName(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		return md["client"][0]
	}
	return "no-client-name"
}

func (s *gorramServer) Ping(ctx context.Context, msg *gorram.IsAlive) (*gorram.IsAlive, error) {
	// Variables to eventually change into config values, fetched from the client's configured interval
	// deadClienttime is the time to wait between alerting after a client has been declared dead
	var deadClienttime time.Duration
	deadClienttime = 30 * time.Second

	client := getClientName(ctx)

	// pingTime is the time to wait before declaring a client dead
	//   Eventually this should be the client's configured interval + 10 seconds or so
	var pingTime time.Duration
	pingTime = time.Duration(s.loadConfig(client).Interval+10) * time.Second

	// This might be redundant since this should always be true
	/*
		if msg.IsAlive {
			log.Println("[TIMER]", client, "is alive!")
		}
	*/

	// Setup a ping timer
	clientTimer, ok := s.clientTimers.timers.Load(client)

	if ok {
		//log.Println("[TIMER]", client, "timer found, resetting.")

		// Reset the client's timer
		clientTimer.(*time.Timer).Reset(pingTime)

	} else {
		//log.Println("[TIMER]", client, "creating new timer for", pingTime, "seconds")

		// Check if the client was dead, and reset it's ticker
		if clientTicker, ok := s.clientTimers.tickers.Load(client); ok {

			//log.Println("[TIMER]", client, "is alive again. Stopping it's deadClientTicker.")

			clientTicker.(*time.Ticker).Stop()
		}
		// create a ticker to store and reference
		ticker := time.NewTicker(deadClienttime)
		s.clientTimers.tickers.Store(client, ticker)
		// Create a timer to store and reference
		timer := time.NewTimer(pingTime)
		s.clientTimers.timers.Store(client, timer)

		// Fire off a goroutine that expires in 60 seconds, then ticking every 30 seconds
		go deadClientTicker(client, &s.clientTimers, *s.cfg)
	}

	log.Println("[TIMER] Number of goroutines:", runtime.NumGoroutine())

	return msg, nil
}

func deadClientTicker(clientName string, c *clientTimers, cfg config) {
	timer, ok := c.timers.Load(clientName)
	if !ok {
		log.Fatalln("[TIMER] Error: no timer for", clientName)
	}
	ticker, ok := c.tickers.Load(clientName)
	if !ok {
		log.Fatalln("[TIMER] Error: no ticker for", clientName)
	}

	<-timer.(*time.Timer).C

	//log.Println("[TIMER]", clientName, "is dead. Deleting it's timer.")

	c.timers.Delete(clientName)

	for t := range ticker.(*time.Ticker).C {
		//log.Println("[TIMER]", t, clientName, "is dead")

		alert(cfg, clientName, gorram.Issue{
			Title:   "Dead Client",
			Message: fmt.Sprintf("%v is dead, since %v", clientName, t),
		})
	}

}

func (s *gorramServer) RecordIssue(stream gorram.Reporter_RecordIssueServer) error {

	//startTime := time.Now()

	for {
		issue, err := stream.Recv()
		if err == io.EOF {

			//log.Println("Time since issues started being submitted:", time.Since(startTime).String())

			return stream.SendAndClose(&gorram.Submitted{
				SuccessfullySubmitted: true,
			})
		}
		if err != nil {
			return err
		}
		// Record issue
		alert(*s.cfg, getClientName(stream.Context()), *issue)

		//log.Println("Time since issue was submitted:", time.Since(time.Unix(issue.TimeSubmitted, 0)).String())

	}
}

func (s *gorramServer) loadConfig(client string) gorram.Config {
	// Attempt to read the config.toml, and then if it has [clientname] in it, unmarshal the config from there
	clientCfg, isThere := s.clientCfg.Load(client)
	if isThere {
		return *clientCfg.(*gorram.Config)
	}

	// Default config values:
	return gorram.Config{
		Interval: 60,
		Load: &gorram.Load{
			MaxLoad: 0.5,
		},
		Disk: []*gorram.DiskSpace{
			&gorram.DiskSpace{
				Partition: "/",
				MaxUsage:  10.0,
			},
		},
	}
}

func (s *gorramServer) SendConfig(ctx context.Context, req *gorram.ConfigRequest) (*gorram.Config, error) {
	// TODO: Implement client-side SHA1 summing, once client-side config-reloading is implemented
	/*
		if req.CfgSha1Sum != "1a21a32" {
			log.Println("config sha1 sum does not match server-side.")
		}
	*/
	clientName := getClientName(ctx)

	// Load config
	cfg := s.loadConfig(clientName)

	return &cfg, nil
}

func (cfg config) authorize(ctx context.Context) error {
	var clientName string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if len(md["secret"]) > 0 && md["secret"][0] == cfg.secretKey {
			return nil
		}
		// Set client name if applicable
		if len(md["client"]) > 0 {
			clientName = md["client"][0]
		}
	}
	err := errors.New("Access Denied")
	log.Println(err, "To Client: "+clientName)
	return err
}

func (cfg config) unaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := cfg.authorize(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func (cfg config) streamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := cfg.authorize(stream.Context()); err != nil {
		return err
	}
	return handler(srv, stream)
}

func alert(cfg config, client string, issue gorram.Issue) {
	switch cfg.alertMethod {
	case "log":
		log.Println("ALERT: ["+client+"]: "+issue.Title+":", issue.Message)
	}
}

func main() {

	// Set config via flags
	confFile := flag.String("conf", "config.toml", "Path to the TOML config file.")
	insecure := flag.Bool("insecure", false, "Disable TLS. Allow insecure client connections.")
	serverAddress := flag.String("listen-address", "127.0.0.1:50000", "Address and port to listen on.")
	serverCert := flag.String("cert", "cert.pem", "Path to the server certificate.")
	serverCertKey := flag.String("key", "cert.key", "Path to the server certificate key.")
	generate := flag.Bool("generate-certs", false, "Generate certs if given.")
	generateHost := flag.String("tls-host", "127.0.0.1", "If generate-certs is specified, override the host in the cert.")
	secret := flag.String("server-secret", "omg12345", "Secret key of the server.")
	alertMethodF := flag.String("alert", "log", "Alert method to use. Right now, log. To come: pushover.")
	flag.Parse()

	cfg := &config{
		secretKey:   *secret,
		alertMethod: *alertMethodF,
		configFile:  *confFile,
	}

	// TLS stuff
	var creds credentials.TransportCredentials
	if *generate {
		// Only generate cert.pem if it do not exist
		if _, err := os.Stat("./cert.pem"); err == nil {
			log.Fatalln("./cert.pem already exists. Not overwriting. Manually remove it and cert.key if you need to re-generate them.")
		}
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

	// Load config.toml here
	var clientCfgs sync.Map
	cfgTree, err := toml.LoadFile(*confFile)
	if err != nil {
		log.Fatalln("Error reading config.toml", err)
	}
	for _, clientName := range cfgTree.Keys() {
		log.Println("Loading config for", clientName, "from config.toml...")
		clientCfgTree := cfgTree.Get(clientName).(*toml.Tree)
		clientCfg := gorram.Config{}
		err := clientCfgTree.Unmarshal(&clientCfg)
		if err != nil {
			log.Fatalln("Error unmarshaling config.toml for client "+clientName+":", err)
		}
		if clientCfg.Interval == 0 {
			log.Println(clientName, "has no interval configured. Setting to 60 seconds.")
			clientCfg.Interval = 60
		}
		clientCfgs.Store(clientName, &clientCfg)
	}

	gs := gorramServer{
		cfg:       cfg,
		clientCfg: &clientCfgs,
	}

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
