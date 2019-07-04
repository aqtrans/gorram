package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"google.golang.org/grpc/keepalive"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gregdel/pushover"

	//"github.com/spf13/pflag"
	//"github.com/spf13/viper"
	_ "github.com/tevjef/go-runtime-metrics/expvar"

	"git.jba.io/go/gorram/certs"
	"git.jba.io/go/gorram/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

type serverConfig struct {
	SecretKey       string
	AlertMethod     string
	PushoverAppKey  string
	PushoverUserKey string
	PushoverDevice  string
	ListenAddress   string
	//Clients         []gorram.Config
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
	clientCfgs       sync.Map
	cfg              serverConfig
	connectedClients gorram.ClientList
	alertsMap        alerts
	/*
		pingTimers    map[string]*time.Timer
		clientList    map[string]chan bool
		clientTickers map[string]*time.Ticker
	*/
}

type alerts struct {
	sync.Mutex
	m map[string]*gorram.Alert
}

type clientTimers struct {
	tickers sync.Map
	timers  sync.Map
}

func getClientName(ctx context.Context) string {
	p, pok := peer.FromContext(ctx)
	if pok {
		tlsAuth, tok := p.AuthInfo.(credentials.TLSInfo)
		if tok {
			if len(tlsAuth.State.PeerCertificates) != 0 {
				//log.Println("Client from cert:", tlsAuth.State.PeerCertificates[0].Subject.CommonName)
				return tlsAuth.State.PeerCertificates[0].Subject.CommonName
			}
		}
	}

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
		s.alert(clientName, gorram.Issue{
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

		s.alert(clientName, gorram.Issue{
			Title:   "Dead Client",
			Message: fmt.Sprintf("%v is dead, since %v", clientName, t),
		})
	}

}

func (c *clientTimers) getTimer(clientName string) *time.Timer {
	timer, ok := c.timers.Load(clientName)
	if !ok {
		log.Fatalln("getTimer Error: no timer for", clientName)
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
		s.alert(getClientName(stream.Context()), *issue)

		//log.Println("Time since issue was submitted:", time.Since(time.Unix(issue.TimeSubmitted, 0)).String())

	}
}

func (s *gorramServer) loadClientConfig(client string) gorram.Config {
	// Attempt to read the config.toml, and then if it has [clientname] in it, unmarshal the config from there
	clientCfg, isThere := s.clientCfgs.Load(client)
	if isThere {
		return *clientCfg.(*gorram.Config)
	}

	// Default config values:
	return gorram.Config{
		/*
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
		*/
	}
}

func (s *gorramServer) ConfigSync(ctx context.Context, req *gorram.ConfigRequest) (*gorram.Config, error) {

	clientName := getClientName(ctx)

	log.Println(clientName, "has synced config.")

	// Check if the client was dead, and reset it's ticker
	//s.reviveDeadClient(clientName)

	// Load config
	cfg := s.loadClientConfig(clientName)

	enabledChecks, ok := s.clientCfgs.Load(clientName + ".checks")
	if ok {
		cfg.EnabledChecks = enabledChecks.(string)
	}

	return &cfg, nil
}

func (cfg serverConfig) authorize(ctx context.Context) error {
	var clientName string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if len(md["secret"]) > 0 && md["secret"][0] == cfg.SecretKey {
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

func (s *gorramServer) alert(client string, issue gorram.Issue) {

	// Tie the issue with the given client name here
	issue.Host = client

	if s.alertsMap.exists(issue) {
		//log.Println(issue.String())
		log.Println("Issue exists. Increasing occurrence count.")
		occurrences := s.alertsMap.count(issue)
		if occurrences < 5 {
			log.Println("Less than 5 occurrences. Continuing alerts.")
		} else if (occurrences % 10) == 0 {
			log.Println("Sending alert", occurrences)
			s.alertsMap.Lock()
			issue.Message = issue.Message + " | Occurrences: " + strconv.FormatInt(occurrences, 10) + "| First occurred:" + time.Unix(s.alertsMap.m[issue.String()].TimeSubmitted, 0).String()
			s.alertsMap.Unlock()
		} else {
			log.Println("Skipping alert...", occurrences)
			return
		}

	} else {
		log.Println("Issue does not exist. Adding to map.")
		a := gorram.Alert{
			Issue:         &issue,
			TimeSubmitted: time.Now().Unix(),
			Occurrences:   1,
		}
		s.alertsMap.add(a)
	}

	switch s.cfg.AlertMethod {
	case "log":
		log.Println("ALERT: "+client+" - "+issue.Title+":", issue.Message)
	case "pushover":
		log.Println("ALERT: "+client+" - "+issue.Title+":", issue.Message)
		app := pushover.New(s.cfg.PushoverAppKey)
		recipient := pushover.NewRecipient(s.cfg.PushoverUserKey)
		message := pushover.NewMessageWithTitle(issue.Message, client+" - "+issue.Title)
		// Set an optional device name to send alerts to
		if s.cfg.PushoverDevice != "" {
			message.DeviceName = s.cfg.PushoverDevice
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
	cfgBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		log.Fatalln("Error reading", confFile, err)
	}
	cfgAst, err := hcl.ParseBytes(cfgBytes)
	if err != nil {
		log.Fatalln("Error parsing", confFile, err)
	}
	list, ok := cfgAst.Node.(*ast.ObjectList)
	if !ok {
		log.Fatalln("CfgAst Node is not an ObjectList")
	}
	clients := list.Filter("Clients")
	for _, v := range clients.Items {
		clientName := v.Keys[0].Token.Value().(string)
		log.Println("Client:", clientName)
		var clientCfg gorram.Config
		hcl.DecodeObject(&clientCfg, v.Val)
		s.clientCfgs.Store(clientName, &clientCfg)
	}
	os.Exit(0)
	/*
		// Load config.toml here
		cfgTree, err := toml.LoadFile(confFile)
		if err != nil {
			log.Fatalln("Error reading config.toml", err)
		}
		for _, clientName := range cfgTree.Keys() {
			// Allow configuring server-specific variables inside a ServerConfig table
			if clientName == "ServerConfig" {
				serverCfgTree := cfgTree.Get(clientName).(*toml.Tree)
				serverCfgTree.Unmarshal(&s.cfg)
				//log.Println(s.cfg)
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

			checkKeys := clientCfgTree.Keys()
			var enabledChecks []string
			for _, v := range checkKeys {
				//log.Println(v)
				if v == "Required" {

				} else if v == "Interval" {

				} else {
					enabledChecks = append(enabledChecks, v)
				}
			}

			// Store the enabled checks
			s.clientCfgs.Store(clientName+".checks", strings.Join(enabledChecks, ","))

			s.clientCfgs.Store(clientName, &clientCfg)
		}
	*/
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

/*
func (a *alerts) exists(client string, alert gorram.Alert, interval int64) (resend, exists bool) {
	a.Lock()
	alertHash := alert.Issue.Title + alert.Issue.Message
	clientAlerts := a.m[client]
	log.Println(len(clientAlerts))
	for i, v := range clientAlerts {
		if alertHash == v.Issue.Title+v.Issue.Message {
			// Increase Occurrences counter
			v.Occurrences = v.Occurrences + 1

			log.Println(v.String())

			// Send the first 2 alerts
			if v.Occurrences < 5 {
				log.Println("Alert is not stale yet.", v.Occurrences)
				a.Unlock()
				return true, false
			}

			if v.Occurrences > 25 {
				log.Println("Alert is stale! Deleting alert from map...")
				//log.Println(len(a.m[client]))
				a.m[client][i] = a.m[client][len(a.m[client])-1]
				a.m[client] = a.m[client][:len(a.m[client])-1]
				//a.m[client] = append(a.m[client][:i], a.m[client][i+1:]...)
				//log.Println(len(a.m[client]))
				a.Unlock()
				return false, false
			}
			a.Unlock()
			return false, true
		}
	}
	a.Unlock()
	return false, false
}
*/

func (a *alerts) add(alert gorram.Alert) {
	a.Lock()
	if len(a.m) > 20 {
		log.Println("issues map is greater than 20", len(a.m))
	}
	a.m[alert.Issue.String()] = &alert
	a.Unlock()
}

func (a *alerts) count(issue gorram.Issue) int64 {
	a.Lock()
	v := a.m[issue.String()]
	v.Occurrences = v.Occurrences + 1
	a.Unlock()
	return v.Occurrences
}

func (a *alerts) exists(issue gorram.Issue) bool {
	a.Lock()
	_, alertExists := a.m[issue.String()]
	a.Unlock()
	return alertExists
}

func (s *gorramServer) checkRequiredClients(k, v interface{}) bool {
	if clientName, isString := k.(string); isString {
		if _, ok := s.connectedClients.Clients[clientName]; !ok {
			clientCfg, isThere := s.clientCfgs.Load(clientName)
			if isThere {
				if actualClientCfg, isCfg := clientCfg.(*gorram.Config); isCfg {
					if actualClientCfg.Required {
						log.Println(k, "NOT CONNECTED! ALERT!")
						s.alert(clientName, gorram.Issue{
							Title:   "Client Offline",
							Message: clientName + " has not connected",
						})
					}
				}

			}

		}
	}
	return true
}

func main() {

	// Set config via flags
	confFile := flag.String("conf", "config.hcl", "Path to the TOML config file.")
	insecure := flag.Bool("insecure", false, "Disable TLS. Allow insecure client connections.")
	generateCAcert := flag.Bool("generate-ca", false, "Generate CA certificates, at cacert.pem and cacert.key.")
	//serverAddress := flag.String("listen-address", "127.0.0.1:50000", "Address and port to listen on.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the server certificate.")
	//serverCertKey := flag.String("key", "cert.key", "Path to the server certificate key.")
	//secret := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//alertMethodF := flag.String("alert", "log", "Alert method to use. Right now, log. To come: pushover.")
	flag.Parse()

	/*
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
	*/

	if *generateCAcert {
		log.Println("Generating cacert.pem and cacert.key...")
		certs.GenerateCACert()
	}

	gs := gorramServer{
		cfg:              serverConfig{},
		clientCfgs:       *new(sync.Map),
		connectedClients: *new(gorram.ClientList),
	}

	gs.loadConfig(*confFile)

	// Expose expvars on port 50001
	go func() {
		http.ListenAndServe("127.0.0.1:50001", nil)
	}()

	// TLS stuff
	var creds credentials.TransportCredentials
	/*
		if *generate {
			// Only generate cert.pem if it do not exist
			if _, err := os.Stat(*serverCert); err == nil {
				log.Fatalln(*serverCert, "already exists. Not overwriting. Manually remove it and cert.key if you need to re-generate them.")
			}
			log.Println("Generating certs to", *serverCert, "and", *serverCertKey)
			generateCerts(*generateHost, *serverCert, *serverCertKey)
		}
	*/

	if !*insecure {

		// If a certificate at server.pem exists, load it, otherwise generate one dynamically
		var tlsCert tls.Certificate
		if _, err := os.Stat("server.pem"); err == nil {

			// Load static cert at server.pem:
			log.Println("server.pem exists. Loading cert.")
			tlsCert, err = tls.LoadX509KeyPair("server.pem", "server.key")
			if err != nil {
				log.Fatalln("Error reading", "server.pem", err)
			}
		} else {
			// Check that CA cert required to sign/generate server and client exists, generating if needed:
			if _, err := os.Stat("cacert.pem"); err != nil {
				log.Println("CA certificate at cacert.pem does not exist, generating it...")
				certs.GenerateCACert()
			}

			// Generate certificates dynamically:
			log.Println("Generating certificate dynamically...")
			var tlsHost string
			tlsHost, _, err := net.SplitHostPort(gs.cfg.ListenAddress)
			if err != nil {
				log.Println("Error parsing ListenAddress from config; Watch out for TLS issues.", err)
				tlsHost = gs.cfg.ListenAddress
			}
			tlsCert = certs.GenerateServerCert(tlsHost, "cacert.pem", "cacert.key")
		}

		caCert, err := ioutil.ReadFile("cacert.pem")
		if err != nil {
			log.Fatalln("Error reading", "cacert.pem", err)
		}
		certPool := x509.NewCertPool()
		if success := certPool.AppendCertsFromPEM(caCert); !success {
			log.Fatalln("cannot append certs from PEM")
		}

		creds = credentials.NewTLS(&tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    certPool,
		})
		/*
			var err error
			creds, err = credentials.NewServerTLSFromFile(*serverCert, *serverCertKey)
			if err != nil {
				log.Fatal("Error with certs:", err)
			}
		*/
	}

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Setup the TCP port to listen on
	lis, err := net.Listen("tcp", gs.cfg.ListenAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("Listening on", gs.cfg.ListenAddress)

	sh := statHandler{}

	kp := keepalive.ServerParameters{
		MaxConnectionIdle: 5 * time.Minute,
		Time:              15 * time.Minute,
		Timeout:           20 * time.Second,
	}
	kpe := keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second,
		PermitWithoutStream: true,
	}

	var server *grpc.Server
	if *insecure {
		server = grpc.NewServer(grpc.StatsHandler(&sh), grpc.UnaryInterceptor(gs.cfg.unaryInterceptor), grpc.KeepaliveParams(kp), grpc.KeepaliveEnforcementPolicy(kpe))
	} else {
		server = grpc.NewServer(grpc.Creds(creds), grpc.StatsHandler(&sh), grpc.UnaryInterceptor(gs.cfg.unaryInterceptor), grpc.KeepaliveParams(kp), grpc.KeepaliveEnforcementPolicy(kpe))
	}

	gs.alertsMap.m = make(map[string]*gorram.Alert)

	gs.connectedClients.Clients = make(map[string]*gorram.Client)

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
					log.Println("Error watching config.toml:", err)
				}
			}
		}
	}()

	err = watcher.Add(*confFile)
	if err != nil {
		log.Fatal("Error watching config.toml:", err)
	}

	// Now start checking if clients flagged as 'required' have connected:
	// Currently checking every 5 minutes; May want to work this into a config variable
	ticker := time.NewTicker(300 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				gs.clientCfgs.Range(gs.checkRequiredClients)
				//gs.isClientConnected
			case <-quit:
				ticker.Stop()
				return
			}
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
	ticker.Stop()
	watcher.Close()
	server.GracefulStop()

}
