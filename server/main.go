package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	//"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gregdel/pushover"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"

	_ "github.com/tevjef/go-runtime-metrics/expvar"

	"git.jba.io/go/gorram/certs"
	gorram "git.jba.io/go/gorram/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
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
	TLSHostname     string
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
	log.Infoln("Inbound connection from", tagInfo.RemoteAddr)
	return ctx
}

func (s *statHandler) HandleConn(ctx context.Context, connStats stats.ConnStats) {
	switch connStats.(type) {
	case *stats.ConnBegin:
		log.Infoln("Connection has begun")
	case *stats.ConnEnd:
		log.Infoln("Connection has ended")
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
		log.WithFields(log.Fields{
			"client": client,
		}).Infoln("Client config mismatch. Setting cfgOutOfDate to true.")
		cfgOutOfDate.CfgOutOfSync = true
	}

	// pingTime is the time to wait before declaring a client dead
	var pingTime time.Duration
	pingTime = time.Duration(s.loadClientConfig(client).Interval*2) * time.Second

	// Setup a ping timer
	clientTimer, ok := s.clientTimers.timers.Load(client)

	if ok {
		ct := clientTimer.(*time.Timer)
		// Reset the client's timer
		if !ct.Stop() {
			log.WithFields(log.Fields{
				"client": client,
			}).Debugln("ct.Stop() hit. Draining channel.")
			<-ct.C
		}
		ct.Reset(pingTime)

	} else {
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

	return &cfgOutOfDate, nil
}

// reviveDeadClient checks and resets the ticket a dead client sets off
func (s *gorramServer) reviveDeadClient(clientName string) {
	if clientTicker, ok := s.clientTimers.tickers.Load(clientName); ok {
		s.alert(clientName, gorram.Issue{
			Title:   "Client Revived",
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
	log.WithFields(log.Fields{
		"client": clientName,
	}).Debugln("timer has expired.")
	timer.Stop()

	s.clientTimers.timers.Delete(clientName)

	for t := range ticker.C {
		s.alert(clientName, gorram.Issue{
			Title:   "Dead Client",
			Message: fmt.Sprintf("%v is dead, since %v", clientName, t),
		})
	}

}

func (c *clientTimers) getTimer(clientName string) *time.Timer {
	timer, ok := c.timers.Load(clientName)
	if !ok {
		log.Fatalln("[TIMER] getTimer Error: no timer for", clientName)
	}
	return timer.(*time.Timer)
}

func (c *clientTimers) getTicker(clientName string) *time.Ticker {
	ticker, ok := c.tickers.Load(clientName)
	if !ok {
		log.Fatalln("[TIMER] getTimer Error: no ticker for", clientName)
	}
	return ticker.(*time.Ticker)
}

func (s *gorramServer) RecordIssue(stream gorram.Reporter_RecordIssueServer) error {

	for {
		issue, err := stream.Recv()
		if err == io.EOF {

			return stream.SendAndClose(&gorram.Submitted{
				SuccessfullySubmitted: true,
			})
		}
		if err != nil {
			return err
		}
		// Record issue
		s.alert(getClientName(stream.Context()), *issue)

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

	log.WithFields(log.Fields{
		"client": clientName,
	}).Debugln("Client has synced config.")

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
	var givenSecret string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if len(md["secret"]) > 0 && md["secret"][0] == cfg.SecretKey {
			return nil
		}
		// Set client name if applicable
		if len(md["client"]) > 0 {
			clientName = md["client"][0]
		}
		if len(md["secret"]) > 0 {
			givenSecret = md["secret"][0]
		}
	}
	err := errors.New("Access Denied")
	log.WithFields(log.Fields{
		"client": clientName,
		"secret": givenSecret,
	}).Infoln("Access denied due to invalid secret.")
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
		occurrences := s.alertsMap.count(issue)

		log.WithFields(log.Fields{
			"client":      client,
			"issue":       issue.String(),
			"occurrences": occurrences,
		}).Debugln("Issue exists. Increasing occurrence count.")

		if occurrences < 5 {
			log.WithFields(log.Fields{
				"client":      client,
				"issue":       issue.String(),
				"occurrences": occurrences,
			}).Debugln("Less than 5 occurrences. Continuing alerts.")
		} else if (occurrences % 10) == 0 {
			log.WithFields(log.Fields{
				"client":      client,
				"issue":       issue.String(),
				"occurrences": occurrences,
			}).Debugln("Sending alert as it meets occurrences count.")
			s.alertsMap.Lock()
			issue.Message = issue.Message + " | Occurrences: " + strconv.FormatInt(occurrences, 10) + "| First occurred:" + time.Unix(s.alertsMap.m[issue.String()].TimeSubmitted, 0).String()
			s.alertsMap.Unlock()
		} else {
			log.WithFields(log.Fields{
				"client":      client,
				"issue":       issue.String(),
				"occurrences": occurrences,
			}).Debugln("Skipping alert...")
			return
		}

	} else {
		log.WithFields(log.Fields{
			"client": client,
			"issue":  issue.String(),
		}).Debugln("Issue does not exist. Adding to map.")

		a := gorram.Alert{
			Issue:         &issue,
			TimeSubmitted: time.Now().Unix(),
			Occurrences:   1,
		}
		s.alertsMap.add(a)
	}

	switch s.cfg.AlertMethod {
	case "log":
		log.WithFields(log.Fields{
			"client": client,
			"issue":  issue.String(),
		}).Warnln("[ALERT] "+client+" - "+issue.Title+":", issue.Message)
	case "pushover":
		log.WithFields(log.Fields{
			"client": client,
			"issue":  issue.String(),
		}).Debugln("[ALERT] "+client+" - "+issue.Title+":", issue.Message)

		app := pushover.New(s.cfg.PushoverAppKey)
		recipient := pushover.NewRecipient(s.cfg.PushoverUserKey)
		message := pushover.NewMessageWithTitle(issue.Message, client+" - "+issue.Title)
		// Set an optional device name to send alerts to
		if s.cfg.PushoverDevice != "" {
			message.DeviceName = s.cfg.PushoverDevice
		}
		response, err := app.SendMessage(message, recipient)
		if err != nil {
			log.Errorln("Error sending alert to pushover:", err)
			return
		}
		if response.Errors != nil {
			log.Errorln("Pushover returned error(s):", response.Errors.Error())
			return
		}
	}
}

func (s *gorramServer) loadConfig(confFile string) {
	ext := filepath.Ext(confFile)
	switch ext {
	case ".hcl":
		cfgBytes, err := ioutil.ReadFile(confFile)
		if err != nil {
			log.Fatalln("Error reading", confFile, err)
		}
		cfgAst, err := hcl.ParseBytes(cfgBytes)
		if err != nil {
			log.Fatalln("Error parsing", confFile, err)
		}
		// Decode server-level config
		hcl.DecodeObject(&s.cfg, cfgAst.Node)

		list, ok := cfgAst.Node.(*ast.ObjectList)
		if !ok {
			log.Fatalln("CfgAst Node is not an ObjectList")
		}
		clients := list.Filter("Client")
		for _, v := range clients.Items {
			clientName := v.Keys[0].Token.Value().(string)

			log.WithFields(log.Fields{
				"client": clientName,
				"config": confFile,
			}).Debugln("Loaded config for", clientName, "from", confFile)

			// Decode each client-level config
			var clientCfg gorram.Config
			hcl.DecodeObject(&clientCfg, v.Val)

			clientCfgList, aok := v.Val.(*ast.ObjectType)
			if !aok {
				log.Fatalln("Error: clientCfgList is not an ObjectType.")
			}
			var enabledChecks []string
			for _, vv := range clientCfgList.List.Items {
				key := vv.Keys[0].Token.Value().(string)
				if key == "Required" {

				} else if key == "Interval" {

				} else {
					enabledChecks = append(enabledChecks, key)
				}
			}

			if clientCfg.Interval == 0 {
				log.WithFields(log.Fields{
					"client": clientName,
					"config": confFile,
				}).Debugln("No interval configured. Setting to 60 seconds.")
				clientCfg.Interval = 60
			}
			clientCfg.LastUpdated = time.Now().Unix()

			// Store the enabled checks
			s.clientCfgs.Store(clientName+".checks", strings.Join(enabledChecks, ","))
			s.clientCfgs.Store(clientName, &clientCfg)
		}
	case ".toml":
		// Load TOML here
		cfgTree, err := toml.LoadFile(confFile)
		if err != nil {
			log.Fatalln("Error reading", confFile, err)
		}
		for _, clientName := range cfgTree.Keys() {
			// Allow configuring server-specific variables inside a ServerConfig table
			if clientName == "ServerConfig" {
				serverCfgTree := cfgTree.Get(clientName).(*toml.Tree)
				serverCfgTree.Unmarshal(&s.cfg)
				continue
			}

			log.WithFields(log.Fields{
				"client": clientName,
				"config": confFile,
			}).Debugln("Loaded config for", clientName, "from", confFile)

			clientCfgTree := cfgTree.Get(clientName).(*toml.Tree)
			clientCfg := gorram.Config{}
			err := clientCfgTree.Unmarshal(&clientCfg)
			if err != nil {
				log.Fatalln("Error unmarshaling "+confFile+" for client "+clientName+":", err)
			}

			checkKeys := clientCfgTree.Keys()
			var enabledChecks []string
			for _, v := range checkKeys {
				if v == "Required" {

				} else if v == "Interval" {

				} else {
					enabledChecks = append(enabledChecks, v)
				}
			}

			if clientCfg.Interval == 0 {
				log.WithFields(log.Fields{
					"client": clientName,
					"config": confFile,
				}).Debugln("No interval configured. Setting to 60 seconds.")
				clientCfg.Interval = 60
			}
			clientCfg.LastUpdated = time.Now().Unix()

			// Store the enabled checks
			s.clientCfgs.Store(clientName+".checks", strings.Join(enabledChecks, ","))
			s.clientCfgs.Store(clientName, &clientCfg)
		}
	default:
		log.Fatalln("Only able to load TOML and HCL files currently. Unable to load", confFile)
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
		log.WithFields(log.Fields{
			"client": clientName,
		}).Infoln("Deleted from client list.")
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
		log.WithFields(log.Fields{
			"client": clientName,
		}).Debugln("ERR: no peer info in context")
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
		log.WithFields(log.Fields{
			"client":      alert.Issue.Host,
			"alert":       alert.String(),
			"occurrences": alert.Occurrences,
		}).Debugln("issues map is greater than 20", len(a.m))
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

func (a *alerts) get(issue gorram.Issue) *gorram.Alert {
	a.Lock()
	theAlert, alertExists := a.m[issue.String()]
	if alertExists {
		a.Unlock()
		return theAlert
	} else {
		a.Unlock()
		return nil
	}
}

func (s *gorramServer) checkRequiredClients(k, v interface{}) bool {
	if clientName, isString := k.(string); isString {
		if _, ok := s.connectedClients.Clients[clientName]; !ok {
			clientCfg, isThere := s.clientCfgs.Load(clientName)
			if isThere {
				if actualClientCfg, isCfg := clientCfg.(*gorram.Config); isCfg {
					if actualClientCfg.Required {
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
	sslPath := flag.String("ssl-path", "/etc/gorram/", "Path to read/write SSL certs from.")
	//serverAddress := flag.String("listen-address", "127.0.0.1:50000", "Address and port to listen on.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the server certificate.")
	//serverCertKey := flag.String("key", "cert.key", "Path to the server certificate key.")
	//secret := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//alertMethodF := flag.String("alert", "log", "Alert method to use. Right now, log. To come: pushover.")
	flag.Parse()

	if *generateCAcert {
		log.Infoln("Generating cacert.pem and cacert.key...")
		certs.GenerateCACert(*sslPath)
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

	if !*insecure {
		// If a certificate at server.pem exists, load it, otherwise generate one dynamically
		var tlsCert tls.Certificate
		caCertPath := filepath.Join(*sslPath, "cacert.pem")
		serverCertPath := filepath.Join(*sslPath, "server.pem")
		serverKeyPath := filepath.Join(*sslPath, "server.key")
		if _, err := os.Stat(serverCertPath); err == nil {
			// Load static cert at server.pem:
			log.Debugln("server.pem exists. Loading cert.")
			tlsCert, err = tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
			if err != nil {
				log.Fatalln("Error reading", serverCertPath, err)
			}
		} else {
			// Check that CA cert required to sign/generate server and client exists, generating if needed:
			if _, err := os.Stat(caCertPath); err != nil {
				log.Debugln("CA certificate at cacert.pem does not exist, generating it...")
				certs.GenerateCACert(*sslPath)
			}
			// Generate certificates dynamically:
			log.Debugln("Generating certificate dynamically for", gs.cfg.TLSHostname)
			tlsCert = certs.GenerateServerCert(gs.cfg.TLSHostname, *sslPath)
		}

		caCert, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			log.Fatalln("Error reading", caCertPath, err)
		}
		certPool := x509.NewCertPool()
		if success := certPool.AppendCertsFromPEM(caCert); !success {
			log.Fatalln("Cannot append certs from PEM to certpool.")
		}

		creds = credentials.NewTLS(&tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    certPool,
		})

	}

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Setup the TCP port to listen on
	lis, err := net.Listen("tcp", gs.cfg.ListenAddress)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

	log.Infoln("Listening on", gs.cfg.ListenAddress)

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
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Watch for config.toml changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalln("Error watching config file for changes:", err)
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
					log.Errorln("Error watching config.toml:", err)
				}
			}
		}
	}()

	err = watcher.Add(*confFile)
	if err != nil {
		log.Fatalln("Error watching config.toml:", err)
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
		log.Debugln(sig, "signal caught")
		done <- true
	}()

	// When Ctrl+C is caught, do this
	<-done
	log.Infoln("Server exiting...")
	ticker.Stop()
	watcher.Close()
	server.GracefulStop()

}
