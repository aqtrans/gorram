package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	//"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gregdel/pushover"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	_ "net/http/pprof"

	_ "github.com/tevjef/go-runtime-metrics/expvar"

	"git.jba.io/go/gorram/certs"
	"git.jba.io/go/gorram/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

var (
	errUnknownClient = errors.New("Unknown Client Name - Check ClientName in client.yml")
	sha1ver          string // git commit to be set when built
	buildTime        string // date+time to be set when built
)

type serverConfig struct {
	SecretKey   string `yaml:"secret_key,omitempty"`
	AlertMethod string `yaml:"alert_method,omitempty"`
	Pushover    struct {
		AppKey  string `yaml:"app_key,omitempty"`
		UserKey string `yaml:"user_key,omitempty"`
		Device  string `yaml:"device,omitempty"`
	} `yaml:"pushover,omitempty"`
	ListenAddress    string `yaml:"listen_address,omitempty"`
	TLSHostname      string `yaml:"tls_host,omitempty"`
	HeartbeatSeconds int64  `yaml:"heartbeat_seconds,omitempty"`
	Debug            bool   `yaml:"debug,omitempty"`
	Domain           string `yaml:"domain,omitempty"`
}

type statHandler struct {
	list proto.ClientList
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
	//clientTimers
	clientCfgs       sync.Map
	cfg              serverConfig
	connectedClients clients
	alertsMap        alerts
	proto.UnimplementedQuerierServer
	proto.UnimplementedReporterServer
	/*
		pingTimers    map[string]*time.Timer
		clientList    map[string]chan bool
		clientTickers map[string]*time.Ticker
	*/
}

type clients struct {
	sync.Mutex
	m proto.ClientList
}

type alerts struct {
	sync.Mutex
	m map[string]*proto.Alert
}

/*
type clientTimers struct {
	tickers sync.Map
	timers  sync.Map
}
*/

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
func (s *gorramServer) Ping(ctx context.Context, msg *proto.PingMsg) (*proto.PingResponse, error) {
	/*
		// Variables to eventually change into config values, fetched from the client's configured interval
		// deadClienttime is the time to wait between alerting after a client has been declared dead
		var deadClienttime time.Duration
		deadClienttime = 30 * time.Second
	*/

	client := getClientName(ctx)

	// Update LastPingTime
	s.connectedClients.updatePingTime(client)

	// Compare the config last updated time and the last updated received in the ping message
	var cfgOutOfDate proto.PingResponse
	clientCfg, err := s.loadClientConfig(client)
	if err != nil {
		return nil, err
	}
	if msg.CfgLastUpdated != clientCfg.LastUpdated {
		log.WithFields(log.Fields{
			"client": client,
		}).Infoln("Client config mismatch. Setting cfgOutOfDate to true.")
		cfgOutOfDate.CfgOutOfSync = true
	}

	/*
		// pingTime is the time to wait before declaring a client dead
		var pingTime time.Duration
		pingTime = time.Duration(clientCfg.Interval*2) * time.Second

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
	*/

	return &cfgOutOfDate, nil
}

// reviveDeadClient checks if the client ever connected and
//  never cleanly disconnected. If so, an alert is sent,
//  and the LastPingTime is updated.
func (s *gorramServer) reviveDeadClient(clientName string) {
	if s.connectedClients.exists(clientName) {
		s.alert(clientName, proto.Issue{
			Title:   "Client Revived",
			Message: fmt.Sprintf("%v is alive again!", clientName),
		})
		s.connectedClients.updatePingTime(clientName)
	}
}

func (s *gorramServer) RecordIssue(stream proto.Reporter_RecordIssueServer) error {

	for {
		issue, err := stream.Recv()
		if err == io.EOF {

			return stream.SendAndClose(&proto.Submitted{
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

func (s *gorramServer) loadClientConfig(client string) (proto.Config, error) {
	// Attempt to read the config.yml, and then if it has [clientname] in it, unmarshal the config from there
	clientCfg, isThere := s.clientCfgs.Load(client)
	if isThere {
		/*
			if clientCfg == nil {
				return proto.Config{}, errUnknownClient
			}
		*/
		cfg, ok := clientCfg.(*proto.Config)
		if !ok {
			log.Fatalln(cfg, "is not a proto.Config.")
		}
		return *cfg, nil
	}

	// Default config values:
	return proto.Config{}, errUnknownClient
	/*
			gorram.Config{
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
	*/
}

func (s *gorramServer) ConfigSync(ctx context.Context, req *proto.ConfigRequest) (*proto.Config, error) {

	clientName := getClientName(ctx)

	log.WithFields(log.Fields{
		"client": clientName,
	}).Debugln("Client has synced config.")

	// Check if the client was dead, and reset it's ticker
	//s.reviveDeadClient(clientName)

	// Load config
	cfg, err := s.loadClientConfig(clientName)
	if err != nil {
		return nil, err
	}

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

// sendAlert() decides whether to send alerts
//// Uses a very basic cooloff method:
//// - always under 5
//// - less than 50 and divisible by 10
//// - greater than 50 and divisible by 50
//// - greater than 500 and divisible by 100
func sendAlert(i int64) bool {
	if i < 5 {
		return true
	}
	if i < 50 && (i%10) == 0 {
		return true
	}
	if i > 500 && (i%100) == 0 {
		return true
	}
	if i > 50 && (i%50) == 0 {
		return true
	}

	return false
}

func (s *gorramServer) alert(client string, issue proto.Issue) {

	// Tie the issue with the given client name here
	issue.Host = client

	// Expire alerts stale for longer than 1 hour:
	s.alertsMap.expire(issue)

	if s.alertsMap.exists(issue) {
		occurrences := s.alertsMap.count(issue)

		log.WithFields(log.Fields{
			"client":      client,
			"check":       issue.Title,
			"occurrences": occurrences,
		}).Debugln("Issue exists. Increasing occurrence count.", issue.Message)

		if sendAlert(occurrences) {
			// Send alert...
			log.WithFields(log.Fields{
				"client":      client,
				"check":       issue.Title,
				"occurrences": occurrences,
			}).Debugln("Sending alert", issue.Message)
		} else {
			// Skip alert...
			log.WithFields(log.Fields{
				"client":      client,
				"check":       issue.Title,
				"occurrences": occurrences,
			}).Debugln("Skipping alert...", issue.Message)
			return
		}

		/*
			if occurrences < 5 {
				log.WithFields(log.Fields{
					"client":      client,
					"check":       issue.Title,
					"occurrences": occurrences,
				}).Debugln("Less than 5 occurrences. Continuing alerts.", issue.Message)
			} else if (occurrences % 10) == 0 {
				log.WithFields(log.Fields{
					"client":      client,
					"check":       issue.Title,
					"occurrences": occurrences,
				}).Debugln("Sending alert as it meets occurrences count.", issue.Message)
				s.alertsMap.Lock()
				issue.Message = issue.Message + " | Occurrences: " + strconv.FormatInt(occurrences, 10) + "| First occurred:" + time.Unix(s.alertsMap.m[generateMapKey(issue)].TimeSubmitted, 0).String()
				s.alertsMap.Unlock()
			} else {
				log.WithFields(log.Fields{
					"client":      client,
					"check":       issue.Title,
					"occurrences": occurrences,
				}).Debugln("Skipping alert...", issue.Message)
				return
			}
		*/

	} else {
		log.WithFields(log.Fields{
			"client": client,
			"check":  issue.Title,
		}).Debugln("Issue does not exist. Adding to map.", issue.Message)

		a := proto.Alert{
			Issue:         &issue,
			TimeSubmitted: time.Now().Unix(),
			TimeLast:      time.Now().Unix(),
			Occurrences:   1,
		}
		s.alertsMap.add(a)
	}

	//s.alertsMap.mute(generateMapKey(issue))

	log.Debugln("IssueID:", generateMapKey(issue))

	if s.alertsMap.isMuted(issue) {
		log.Println("issue is muted. not sending alert")
		return
	}

	switch s.cfg.AlertMethod {
	case "log":
		log.WithFields(log.Fields{
			"client": client,
			"check":  issue.Title,
		}).Warnln("[ALERT] ", issue.Message)
	case "pushover":
		log.WithFields(log.Fields{
			"client": client,
			"check":  issue.Title,
		}).Debugln("[ALERT] ", issue.Message)

		app := pushover.New(s.cfg.Pushover.AppKey)
		recipient := pushover.NewRecipient(s.cfg.Pushover.UserKey)
		message := pushover.NewMessageWithTitle(issue.Message, client+" - "+issue.Title)
		message.URL = s.cfg.Domain + "/mute?id=" + generateMapKey(issue)
		message.URLTitle = "Mute Issue"
		// Set an optional device name to send alerts to
		if s.cfg.Pushover.Device != "" {
			message.DeviceName = s.cfg.Pushover.Device
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

func (s *gorramServer) loadConfig(confPath string) {
	//ext := filepath.Ext(confFile)

	// Load server config
	serverCfg, err := ioutil.ReadFile(filepath.Join(confPath, "server.yml"))
	if err != nil {
		log.Fatalln("Error reading server.yml:", err)
	}

	// Load client configs from conf.d/*.yml
	cfgFiles, err := ioutil.ReadDir(filepath.Join(confPath, "conf.d"))
	if err != nil {
		log.Fatalln("Error reading configs from conf.d:", err)
	}

	err = yaml.Unmarshal(serverCfg, &s.cfg)
	if err != nil {
		log.Fatalln("Error unmarshaling server.yml:", err)
	}

	log.Println("server config:", s.cfg)

	for _, cfg := range cfgFiles {
		var newCfg proto.Config
		clientName := strings.TrimSuffix(cfg.Name(), filepath.Ext(cfg.Name()))
		filename := cfg.Name()

		// Only read .yml files
		if filepath.Ext(filename) != ".yml" {
			continue
		}

		fullpath := filepath.Join(confPath, "conf.d", filename)
		newBytes, err := ioutil.ReadFile(fullpath)
		if err != nil {
			log.WithFields(log.Fields{
				"config": fullpath,
				"client": clientName,
			}).Fatalln("Error reading client config", err)
		}
		err = yaml.Unmarshal(newBytes, &newCfg)
		if err != nil {
			log.WithFields(log.Fields{
				"config": fullpath,
				"client": clientName,
			}).Fatalln("Error unmarshaling client config", err)
		}

		log.WithFields(log.Fields{
			"config": fullpath,
			"client": clientName,
		}).Debugln("Loaded config from", cfg.Name(), &newCfg)

		// Set a default interval of 60 seconds if not configured
		if newCfg.Interval == 0 {
			log.WithFields(log.Fields{
				"config": fullpath,
				"client": clientName,
			}).Debugln("No interval configured. Setting to 60 seconds.")
			newCfg.Interval = 60
		}

		newCfg.LastUpdated = time.Now().Unix()

		s.clientCfgs.Store(clientName, &newCfg)

	}

	// Set a default HeartbeatSeconds if not set
	if s.cfg.HeartbeatSeconds == 0 {
		log.Println("HeartbeatSeconds is 0, setting to default of 60.")
		s.cfg.HeartbeatSeconds = 60
	}

}

func (s *gorramServer) List(ctx context.Context, qr *proto.QueryRequest) (*proto.ClientList, error) {

	return &s.connectedClients.m, nil
}

func (s *gorramServer) Delete(ctx context.Context, cn *proto.ClientName) (*proto.ClientList, error) {
	clientName := cn.GetName()
	// Stop and delete clientName's ticker, and delete it from the ClientList
	// TODO: Delete timer too?
	if s.connectedClients.exists(clientName) {
		//delete(s.connectedClients.Clients, clientName)
		s.connectedClients.delete(clientName)
		log.WithFields(log.Fields{
			"client": clientName,
		}).Infoln("Deleted from client list.")
	}

	return &s.connectedClients.m, nil
}

func (s *gorramServer) Debug(ctx context.Context, dr *proto.DebugRequest) (*proto.DebugResponse, error) {

	aString := fmt.Sprintf("Connected clients: %v", s.connectedClients.m)
	return &proto.DebugResponse{
		Resp: aString,
	}, nil
}

func (s *gorramServer) Hello(ctx context.Context, req *proto.ConfigRequest) (*proto.Config, error) {

	clientName := getClientName(ctx)

	// Check if the client has connected before
	s.reviveDeadClient(clientName)

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
	c := proto.Client{
		Name:         clientName,
		Address:      clientAddress,
		LastPingTime: time.Now().Unix(),
	}
	s.connectedClients.add(c)

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

// MapKey should consist of host+title, allowing message to continue updating
// This allows disk space and other alerts to change without unmuting
func generateMapKey(i proto.Issue) string {
	return base64.RawURLEncoding.EncodeToString([]byte(i.Host + i.Title))
}

func (a *alerts) add(alert proto.Alert) {
	a.Lock()
	if len(a.m) > 20 {
		log.WithFields(log.Fields{
			"client":      alert.Issue.Host,
			"alert":       alert.String(),
			"occurrences": alert.Occurrences,
		}).Debugln("issues map is greater than 20", len(a.m))
	}
	a.m[generateMapKey(*alert.Issue)] = &alert
	a.Unlock()
}

// count increases the number of occurrences and returns it
//  it should only be called in alert(), ensuring the occurrences always increase
//  TimeLast is updated as well, to track stale alerts
func (a *alerts) count(issue proto.Issue) int64 {
	a.Lock()
	v := a.m[generateMapKey(issue)]
	v.Occurrences = v.Occurrences + 1
	v.TimeLast = time.Now().Unix()
	a.Unlock()
	return v.Occurrences
}

func (a *alerts) exists(issue proto.Issue) bool {
	a.Lock()
	_, alertExists := a.m[generateMapKey(issue)]
	a.Unlock()
	return alertExists
}

func (a *alerts) get(issue proto.Issue) *proto.Alert {
	a.Lock()
	theAlert, alertExists := a.m[generateMapKey(issue)]
	if alertExists {
		a.Unlock()
		return theAlert
	}

	a.Unlock()
	return nil
}

func (a *alerts) mute(issueID string) {
	a.Lock()
	v := a.m[issueID]
	v.Muted = true
	a.Unlock()
}

func (a *alerts) isMuted(issue proto.Issue) bool {
	var isIt bool
	a.Lock()
	v := a.m[generateMapKey(issue)]
	isIt = v.Muted
	a.Unlock()
	return isIt
}

// expire expires issues that have been stale for 1 hour
func (a *alerts) expire(issue proto.Issue) {
	a.Lock()
	issueID := generateMapKey(issue)
	v, alertExists := a.m[issueID]

	if alertExists {

		lastOccurrence := time.Since(time.Unix(v.TimeLast, 0))

		if lastOccurrence.Hours() > 1.00 {
			log.WithFields(log.Fields{
				"issue": v.Issue.Title,
				"host":  v.Issue.Host,
			}).Infoln("Expiring alert")

			delete(a.m, issueID)
		}

	}

	a.Unlock()
}

func (c *clients) add(client proto.Client) {
	c.Lock()
	c.m.Clients[client.Name] = &client
	c.Unlock()
}

func (c *clients) exists(clientName string) bool {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	c.Unlock()
	return clientExists
}

func (c *clients) get(clientName string) *proto.Client {
	c.Lock()
	theClient, clientExists := c.m.Clients[clientName]
	if clientExists {
		c.Unlock()
		return theClient
	}

	c.Unlock()
	return nil
}

func (c *clients) delete(clientName string) {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	if clientExists {
		c.Unlock()
		return
	}
	delete(c.m.Clients, clientName)

	c.Unlock()
	return
}

func (c *clients) updatePingTime(clientName string) {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	if clientExists {
		c.m.Clients[clientName].LastPingTime = time.Now().Unix()

		c.Unlock()
		return
	}
	c.Unlock()
	return
}

func (c *clients) expired(clientName string, pingInterval int64) bool {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	if clientExists {
		now := time.Now()
		lastPingTime := time.Unix(c.m.Clients[clientName].LastPingTime, 0)
		// If client hasn't pinged in pingInterval * 2, consider it expired
		log.Debugln(clientName, "difference between now and last ping time:", now.Sub(lastPingTime).String())
		if now.Sub(lastPingTime).Seconds() > float64(pingInterval*2) {
			c.Unlock()
			return true
		}
		c.Unlock()
		return false
	}
	c.Unlock()
	return false
}

func (s *gorramServer) checkClients(k, v interface{}) bool {
	if clientName, isString := k.(string); isString {
		clientCfg, err := s.loadClientConfig(clientName)
		if err == errUnknownClient {
			log.Debugln("No config found for", clientName)
			return false
		}
		if err != nil {
			log.Debugln("Error loading config for", clientName)
			return false
		}
		// Check if client is Required and has not connected
		if clientCfg.Required && !s.connectedClients.exists(clientName) {
			s.alert(clientName, proto.Issue{
				Title:   "Client Offline",
				Message: clientName + " has not connected",
			})
		}

		// Check if connected client hasn't pinged in a while, client interval times 2
		if s.connectedClients.exists(clientName) && s.connectedClients.expired(clientName, clientCfg.Interval) {
			log.Debugln(clientName, "has expired")
			// TODO: should add time they've been offline to the alert
			s.alert(clientName, proto.Issue{
				Title:   "Client dropped offline",
				Message: clientName + " has dropped offline",
			})
		}
	}
	return true
}

func (s *gorramServer) muteHandler(w http.ResponseWriter, r *http.Request) {
	issueIDs, ok := r.URL.Query()["id"]
	if !ok {
		w.Write([]byte("No IDs given to mute"))
		return
	}
	/*
		decodedID, err := base64.URLEncoding.DecodeString(issueIDs[0])
		if err != nil {
			log.Println("Error decoding ID", err)
			w.Write([]byte("Error decoding given ID"))
			return
		}
	*/
	s.alertsMap.mute(issueIDs[0])
	w.Write([]byte("Muted"))
}

func (s *gorramServer) listAlertsHandler(w http.ResponseWriter, r *http.Request) {

	s.alertsMap.Lock()

	w.Write([]byte(`<!DOCTYPE html>
	<html lang="en">
	<body>
	<table>
		<thead>
			<tr>
				<th>Alert ID</th>
				<th>Host</th>
				<th>Message</th>
				<th>Title</th>
				<th>Occurrences</th>
				<th>First Time</th>
				<th>Muted</th>
			</tr>
		</thead>
		<tbody>
	`))
	for alertID, v := range s.alertsMap.m {
		fmt.Fprintf(w, `
		<tr>
		<td><a href="/mute?id=%s">%s</a></td>
		<td>%s</td>
		<td>%s</td>
		<td>%s</td>
		<td>%d</td>
		<td>%q</td>
		<td>%t</td>
		</tr>
		`,
			alertID,
			alertID,
			v.Issue.Host,
			v.Issue.Message,
			v.Issue.Title,
			v.Occurrences,
			time.Unix(v.TimeSubmitted, 0).String(),
			v.Muted)
		//w.Write([]byte("host: " + v.Issue.Host + "\n"))
		//w.Write([]byte("msg: " + v.Issue.Message + "\n"))
		//w.Write([]byte("title: " + v.Issue.Title + "\n"))
		//w.Write([]byte("alert: " + v.String() + "\n"))
		//w.Write([]byte("muted: " + v.Muted + "\n"))
		//w.Write([]byte("occurrences: " + v.Occurrences + "\n"))
		//w.Write([]byte("time: " + v.TimeSubmitted + "\n"))
	}
	w.Write([]byte(`</tbody>
	</body>
	</html>`))
	//w.Write([]byte("Total Alerts:", s.alertsMap))
	s.alertsMap.Unlock()
}

func main() {

	formatter := new(log.TextFormatter)
	formatter.TimestampFormat = "01-02-2006 03:04:05pm"
	formatter.FullTimestamp = true
	formatter.DisableLevelTruncation = true
	log.SetFormatter(formatter)

	// Set config via flags
	confPath := flag.String("conf", "/etc/gorram/", "Path where server.yml and a conf.d directory (for client configs) are stored.")
	insecure := flag.Bool("insecure", false, "Disable TLS. Allow insecure client connections.")
	generateCAcert := flag.Bool("generate-ca", false, "Generate CA certificates, at cacert.pem and cacert.key.")
	sslPath := flag.String("ssl-path", "/etc/gorram/", "Path to read/write SSL certs from.")
	debug := flag.Bool("debug", false, "Toggle debug logging.")
	showVersion := flag.Bool("version", false, "Print server version")
	//serverAddress := flag.String("listen-address", "127.0.0.1:50000", "Address and port to listen on.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the server certificate.")
	//serverCertKey := flag.String("key", "cert.key", "Path to the server certificate key.")
	//secret := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//alertMethodF := flag.String("alert", "log", "Alert method to use. Right now, log. To come: pushover.")
	flag.Parse()

	if *showVersion {
		log.Printf("Build date: %s\nGit commit: %s\n", buildTime, sha1ver)
		os.Exit(0)
	}

	// Set debug from flag here to allow debugging config loading and cert generation
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if *generateCAcert {
		log.Infoln("Generating cacert.pem and cacert.key...")
		certs.GenerateCACert(*sslPath)
	}

	gs := gorramServer{
		cfg:              serverConfig{},
		clientCfgs:       *new(sync.Map),
		connectedClients: *new(clients),
	}

	gs.loadConfig(*confPath)

	if gs.cfg.Debug {
		log.SetLevel(log.DebugLevel)
	}

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
			if gs.cfg.TLSHostname == "" {
				log.Fatalln("Error: Unable to dynamically generate server cert with blank hostname. Please configure 'TLSHostname' in server config.")
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

	gs.alertsMap.m = make(map[string]*proto.Alert)

	gs.connectedClients.m.Clients = make(map[string]*proto.Client)

	proto.RegisterReporterServer(server, &gs)

	proto.RegisterQuerierServer(server, &gs)

	// Watch for config.yml changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalln("Error watching config file for changes:", err)
	}

	// Start listening, in a goroutine so SIGINTs can be caught below
	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Expose expvars and pprof on http://127.0.0.1:50001
	go func() {
		http.HandleFunc("/list", gs.listAlertsHandler)
		http.HandleFunc("/mute", gs.muteHandler)
		if err := http.ListenAndServe("127.0.0.1:50001", nil); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Watch config for changes, and every HeartbeatSeconds check for 'dead' clients
	heartbeatTicker := time.NewTicker(time.Duration(gs.cfg.HeartbeatSeconds) * time.Second)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					gs.loadConfig(*confPath)
				}
			case err := <-watcher.Errors:
				if err != nil {
					log.Errorln("Error watching config files:", err)
				}
			case <-heartbeatTicker.C:
				gs.clientCfgs.Range(gs.checkClients)
				//gs.isClientConnected
			case <-done:
				heartbeatTicker.Stop()
				return
			}
		}
	}()

	// Watch confPath/server.yml and confPath/conf.d/ for changes
	serverCfg := filepath.Join(*confPath, "server.yml")
	clientCfgs := filepath.Join(*confPath, "conf.d")
	err = watcher.Add(serverCfg)
	if err != nil {
		log.Fatalln("Error watching server.yml:", err)
	}
	err = watcher.Add(clientCfgs)
	if err != nil {
		log.Fatalln("Error watching conf.d:", err)
	}

	// Listen for Ctrl+C
	go func() {
		sig := <-sigs
		log.Debugln(sig, "signal caught")
		done <- true
	}()

	// When Ctrl+C is caught, do this
	<-done
	log.Infoln("Server exiting...")
	heartbeatTicker.Stop()
	watcher.Close()
	server.Stop()
}
