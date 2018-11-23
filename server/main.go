package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gregdel/pushover"
	"github.com/pelletier/go-toml"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	_ "github.com/tevjef/go-runtime-metrics/expvar"

	"git.jba.io/go/gorram/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

type serverConfig struct {
	secretKey       string
	alertMethod     string
	configFile      string
	pushoverAppKey  string
	pushoverUserKey string
	pushoverDevice  string
}

type statHandler struct {
	list gorram.ClientList
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
	switch connStats.(type) {
	case *stats.ConnBegin:
		log.Println("Connection has begun")
	case *stats.ConnEnd:
		log.Println("Connection has ended")
	}

}

type gorramServer struct {
	clientTimers
	clientCfg        sync.Map
	cfg              serverConfig
	connectedClients gorram.ClientList
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

// Ping handles the dead-client detection functionality
//   It works by spawning a Timer and Ticker for each client
//   - The timer is reset on every successful ping
//   - The ticker triggers the dead-client alerts, once the above timer has expired
func (s *gorramServer) Ping(ctx context.Context, msg *gorram.PingMsg) (*gorram.PingResponse, error) {
	/*
		// Variables to eventually change into config values, fetched from the client's configured interval
		// deadClienttime is the time to wait between alerting after a client has been declared dead
		var deadClienttime time.Duration
		deadClienttime = 30 * time.Second
	*/

	client := getClientName(ctx)

	// Compare the config last updated time and the last updated received in the ping message
	var cfgOutOfDate gorram.PingResponse
	if msg.CfgLastUpdated != s.loadClientConfig(client).LastUpdated {
		log.Println("Config mismatch. Setting cfgOutOfDate to true.")
		cfgOutOfDate.CfgOutOfSync = true
	}

	// pingTime is the time to wait before declaring a client dead
	var pingTime time.Duration
	pingTime = time.Duration(s.loadClientConfig(client).Interval*2) * time.Second

	// Setup a ping timer
	clientTimer, ok := s.clientTimers.timers.Load(client)

	if ok {
		//log.Println("[TIMER]", client, "timer found, resetting.")
		ct := clientTimer.(*time.Timer)
		// Reset the client's timer
		if !ct.Stop() {
			log.Println("ct.Stop() hit. Draining channel.")
			<-ct.C
		}
		ct.Reset(pingTime)

	} else {
		//log.Println("[TIMER]", client, "creating new timer for", pingTime, "seconds")

		// Check if the client was dead, and reset it's ticker
		s.reviveDeadClient(client)

		// create a ticker to store and reference
		ticker := time.NewTicker(pingTime)
		s.clientTimers.tickers.Store(client, ticker)

		// Create a timer to store and reference
		timer := time.NewTimer(pingTime)
		s.clientTimers.timers.Store(client, timer)

		// Fire off a goroutine that expires in 60 seconds, then ticking every 30 seconds
		go s.deadClientTicker(client)
	}

	//log.Println("[TIMER] Number of goroutines:", runtime.NumGoroutine())

	return &cfgOutOfDate, nil
}

// reviveDeadClient checks and resets the ticket a dead client sets off
func (s *gorramServer) reviveDeadClient(clientName string) {
	if clientTicker, ok := s.clientTimers.tickers.Load(clientName); ok {
		//log.Println("[TIMER]", client, "is alive again. Stopping it's deadClientTicker.")
		alert(s.cfg, clientName, gorram.Issue{
			Title:   "Dead Client Alive",
			Message: fmt.Sprintf("%v is alive again!", clientName),
		})
		clientTicker.(*time.Ticker).Stop()
		s.clientTimers.tickers.Delete(clientName)
	}
}

func (s *gorramServer) deadClientTicker(clientName string) {
	timer := s.clientTimers.getTimer(clientName)
	ticker := s.clientTimers.getTicker(clientName)

	// This should block until the given clients timer has not been reset, considering the client dead
	<-timer.C
	log.Println(clientName, "timer has expired.")
	timer.Stop()

	//log.Println("[TIMER]", clientName, "is dead. Deleting it's timer.")

	s.clientTimers.timers.Delete(clientName)

	for t := range ticker.C {
		//log.Println("[TIMER]", t, clientName, "is dead")

		alert(s.cfg, clientName, gorram.Issue{
			Title:   "Dead Client",
			Message: fmt.Sprintf("%v is dead, since %v", clientName, t),
		})
	}

}

func (c *clientTimers) getTimer(clientName string) *time.Timer {
	timer, ok := c.timers.Load(clientName)
	if !ok {
		log.Fatalln("[TIMER] Error: no timer for", clientName)
	}
	return timer.(*time.Timer)
}

func (c *clientTimers) getTicker(clientName string) *time.Ticker {
	ticker, ok := c.tickers.Load(clientName)
	if !ok {
		log.Fatalln("[TIMER] Error: no ticker for", clientName)
	}
	return ticker.(*time.Ticker)
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
		alert(s.cfg, getClientName(stream.Context()), *issue)

		//log.Println("Time since issue was submitted:", time.Since(time.Unix(issue.TimeSubmitted, 0)).String())

	}
}

func (s *gorramServer) loadClientConfig(client string) gorram.Config {
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

func (s *gorramServer) ConfigSync(ctx context.Context, req *gorram.ConfigRequest) (*gorram.Config, error) {

	clientName := getClientName(ctx)

	log.Println(clientName, "has synced config.")

	// Check if the client was dead, and reset it's ticker
	//s.reviveDeadClient(clientName)

	// Load config
	cfg := s.loadClientConfig(clientName)

	return &cfg, nil
}

func (cfg serverConfig) authorize(ctx context.Context) error {
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

func (cfg serverConfig) unaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := cfg.authorize(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func (cfg serverConfig) streamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := cfg.authorize(stream.Context()); err != nil {
		return err
	}
	return handler(srv, stream)
}

func alert(cfg serverConfig, client string, issue gorram.Issue) {
	switch cfg.alertMethod {
	case "log":
		log.Println("ALERT: ["+client+"]: "+issue.Title+":", issue.Message)
	case "pushover":
		log.Println("ALERT: ["+client+"]: "+issue.Title+":", issue.Message)
		app := pushover.New(cfg.pushoverAppKey)
		recipient := pushover.NewRecipient(cfg.pushoverUserKey)
		message := pushover.NewMessageWithTitle(issue.Message, "["+client+"]: "+issue.Title)
		// Set an optional device name to send alerts to
		if cfg.pushoverDevice != "" {
			message.DeviceName = cfg.pushoverDevice
		}
		response, err := app.SendMessage(message, recipient)
		if err != nil {
			log.Println("error sending alert to pushover:", err)
			return
		}
		if response.Errors != nil {
			log.Println("Pushover returned error(s):", response.Errors.Error())
			return
		}
	}
}

func (s *gorramServer) loadConfig(confFile string) {
	// Load config.toml here
	cfgTree, err := toml.LoadFile(confFile)
	if err != nil {
		log.Fatalln("Error reading config.toml", err)
	}
	for _, clientName := range cfgTree.Keys() {
		// Allow configuring server-specific variables inside a ServerConfig table
		if clientName == "ServerConfig" {
			serverCfgTree := cfgTree.Get(clientName).(*toml.Tree)
			if serverCfgTree.Has("secretKey") {
				s.cfg.secretKey = serverCfgTree.Get("secretKey").(string)
			}
			if serverCfgTree.Has("pushoverAppKey") {
				s.cfg.pushoverAppKey = serverCfgTree.Get("pushoverAppKey").(string)
			}
			if serverCfgTree.Has("pushoverUserKey") {
				s.cfg.pushoverUserKey = serverCfgTree.Get("pushoverUserKey").(string)
			}
			if serverCfgTree.Has("pushoverDevice") {
				s.cfg.pushoverDevice = serverCfgTree.Get("pushoverDevice").(string)
			}
			if serverCfgTree.Has("alertMethod") {
				s.cfg.alertMethod = serverCfgTree.Get("alertMethod").(string)
			}
			continue
		}
		log.Println("Loaded config for", clientName, "from config.toml...")
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
		clientCfg.LastUpdated = time.Now().Unix()
		s.clientCfg.Store(clientName, &clientCfg)
	}
}

func (s *gorramServer) List(ctx context.Context, qr *gorram.QueryRequest) (*gorram.ClientList, error) {

	return &s.connectedClients, nil
}

func (s *gorramServer) Delete(ctx context.Context, cn *gorram.ClientName) (*gorram.ClientList, error) {
	clientName := cn.GetName()
	// Stop and delete clientName's ticker, and delete it from the ClientList
	// TODO: Delete timer too?
	if clientTicker, ok := s.clientTimers.tickers.Load(clientName); ok {
		clientTicker.(*time.Ticker).Stop()
		s.clientTimers.tickers.Delete(clientName)
		delete(s.connectedClients.Clients, clientName)
		log.Println(clientName, "has been deleted from client list.")
	}

	return &s.connectedClients, nil
}

func (s *gorramServer) Debug(ctx context.Context, dr *gorram.DebugRequest) (*gorram.DebugResponse, error) {
	timers := make(map[interface{}]interface{})
	s.clientTimers.timers.Range(func(k, v interface{}) bool {
		timers[k] = v
		return true
	})
	tickers := make(map[interface{}]interface{})
	s.clientTimers.tickers.Range(func(k, v interface{}) bool {
		tickers[k] = v
		return true
	})

	aString := fmt.Sprintf("Connected clients: %s | Timers: %s | Tickers: %s", s.connectedClients.String(), timers, tickers)
	return &gorram.DebugResponse{
		Resp: aString,
	}, nil
}

func (s *gorramServer) Hello(ctx context.Context, req *gorram.ConfigRequest) (*gorram.Config, error) {

	clientName := getClientName(ctx)

	var clientAddress string
	p, ok := peer.FromContext(ctx)
	if !ok {
		log.Println("ERR: no peer info in context for", clientName)
		clientAddress = "N/A"
	} else {
		clientAddress = p.Addr.String()
	}

	// As this should only be called on client connection, record the client name and address here
	s.connectedClients.Clients[clientName] = &gorram.Client{
		Name:    clientName,
		Address: clientAddress,
	}

	// Reset and then delete the ticker for the client
	s.reviveDeadClient(clientName)

	return s.ConfigSync(ctx, req)
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

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	// Viper config.
	viper.SetDefault("ServerAddress", "127.0.0.1:5000")
	viper.SetDefault("Insecure", false)
	viper.SetDefault("Cert", "cert.pem")
	viper.SetDefault("Key", "cert.key")
	viper.SetDefault("GenerateCerts", false)
	viper.SetDefault("TLSHost", "127.0.0.1")
	viper.SetDefault("SharedSecret", "test")
	viper.SetDefault("AlertMethod", "log")
	viper.SetEnvPrefix("gorram")
	viper.AutomaticEnv()

	viper.SetConfigName("gorram")
	viper.AddConfigPath("/etc/gorram/")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		//panic(fmt.Errorf("Fatal error config file: %s \n", err))
		log.Println("No configuration file loaded - using defaults")
	}

	go func() {
		http.ListenAndServe("127.0.0.1:50001", nil)
	}()

	cfg := serverConfig{
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

	gs := gorramServer{
		cfg:              cfg,
		clientCfg:        *new(sync.Map),
		connectedClients: *new(gorram.ClientList),
	}

	gs.connectedClients.Clients = make(map[string]*gorram.Client)

	gs.loadConfig(*confFile)

	gorram.RegisterReporterServer(server, &gs)

	gorram.RegisterQuerierServer(server, &gs)

	// Start listening, in a goroutine so SIGINTs can be caught below
	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Watch for config.toml changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					gs.loadConfig(*confFile)
				}
			case err := <-watcher.Errors:
				if err != nil {
					log.Println("error:", err)
				}
			}
		}
	}()

	err = watcher.Add(*confFile)
	if err != nil {
		log.Fatal(err)
	}

	// Listen for Ctrl+C
	go func() {
		sig := <-sigs
		log.Println(sig)
		done <- true
	}()

	// When Ctrl+C is caught, do this
	<-done
	log.Println("Server exiting...")
	watcher.Close()
	server.GracefulStop()

}
