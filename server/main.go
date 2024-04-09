package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	//"log"

	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/goccy/go-yaml"
	"github.com/gregdel/pushover"
	log "github.com/sirupsen/logrus"
	"github.com/twitchtv/twirp"
	"google.golang.org/protobuf/proto"

	_ "net/http/pprof"

	_ "github.com/tevjef/go-runtime-metrics/expvar"

	"git.jba.io/go/gorram/certs"
	"git.jba.io/go/gorram/common"
	pb "git.jba.io/go/gorram/proto"
)

var (
	errUnknownClient = errors.New("unknown Client Name - Check ClientName in client.yml")
	errAccessDenied  = errors.New("access denied")
	sha1ver          string // git commit to be set when built
	buildTime        string // date+time to be set when built
)

type serverConfig struct {
	SharedSecret string `yaml:"shared_secret,omitempty"`
	AlertMethod  string `yaml:"alert_method,omitempty"`
	Pushover     struct {
		AppKey  string `yaml:"app_key,omitempty"`
		UserKey string `yaml:"user_key,omitempty"`
		Device  string `yaml:"device,omitempty"`
	} `yaml:"pushover,omitempty"`
	Matrix struct {
		Homeserver string `yaml:"homeserver,omitempty"`
		Username   string `yaml:"username,omitempty"`
		Password   string `yaml:"password,omitempty"`
		SqliteDB   string `yaml:"mautrixdb,omitempty"`
	} `yaml:"matrix,omitempty"`
	ListenAddress    string `yaml:"listen_address,omitempty"`
	HeartbeatSeconds int64  `yaml:"heartbeat_seconds,omitempty"`
	Debug            bool   `yaml:"debug,omitempty"`
	Domain           string `yaml:"domain,omitempty"`
	AlertManagerURL  string `yaml:"alertmanager_url,omitempty"`
	SSLPath          string `yaml:"ssl_path,omitempty"`
	SSLCertPath      string `yaml:"ssl_cert_path,omitempty"`
	SSLKeyPath       string `yaml:"ssl_cert_key_path,omitempty"`
}

type gorramServer struct {
	//clientTimers
	clientCfgs       sync.Map
	cfg              serverConfig
	connectedClients clients
	alertsMap        alerts
	pb.Reporter
	pb.Querier
}

type clients struct {
	sync.Mutex
	m pb.ClientList
}

type alerts struct {
	sync.Mutex
	m map[string]*pb.Alert
}

type jsonClient struct {
	Name    string `json:"client_name"`
	Address string `json:"ip_address"`
	//Token   string `json:"api_token"`
}

type key int

const (
	nameCtxKey    key = 1
	addressCtxKey key = 2
	tokenCtxKey   key = 3
	secretCtxKey  key = 4
)

func WithClientName(base http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		gc := r.Header.Get("Gorram-Client-ID")
		gt := r.Header.Get("Gorram-Token")
		gs := r.Header.Get("Gorram-Secret")
		gip := r.RemoteAddr

		ctx = context.WithValue(ctx, nameCtxKey, gc)
		ctx = context.WithValue(ctx, addressCtxKey, gip)
		ctx = context.WithValue(ctx, tokenCtxKey, gt)
		ctx = context.WithValue(ctx, secretCtxKey, gs)
		r = r.WithContext(ctx)

		base.ServeHTTP(w, r)
	})
}

// Authorize verifies if the client's Gorram-Token matches what the server generated in Hello()
func (s *gorramServer) Authorize(base http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		givenSecret := getClientSecret(r.Context())
		clientName := getClientName(r.Context())

		if clientName == "" {
			log.WithFields(log.Fields{
				"secret": givenSecret,
				"ip":     r.RemoteAddr,
			}).Debugln("blank client name given")

			twirp.WriteError(w, errUnknownClient)
			return
		}

		if givenSecret == "" {
			log.WithFields(log.Fields{
				"token": givenSecret,
				"ip":    r.RemoteAddr,
			}).Debugln("blank shared secret given")

			twirp.WriteError(w, errors.New("invalid shared secret"))
			return
		}

		// Allow if their signed secret can be verified
		if s.verifySharedSecret(givenSecret, clientName) {
			log.Println("secret verified!")
			base.ServeHTTP(w, r)
			return
		}

		log.WithFields(log.Fields{
			"client": clientName,
			"secret": givenSecret,
			"ip":     r.RemoteAddr,
		}).Infoln("Access denied due to invalid secret.")

		twirp.WriteError(w, errAccessDenied)

		/*
			// If they have no token, but trying to say Hello(), let them through
			if givenToken == "" && r.RequestURI == "/twirp/pb.Reporter/Hello" {
				log.Println(clientName, "has no token, but shared secret matches. Allowing through Authorize()...")
				base.ServeHTTP(w, r)
				return
			}

			// If client is re-connecting, let them through to grab another token
			if givenToken == "" && s.connectedClients.exists(clientName) {
				log.Println(clientName, "is reconnecting! Allowing through Authorize()...")
				base.ServeHTTP(w, r)
				return
			}

			clientCfg := s.connectedClients.get(clientName)
			if clientCfg == nil {
				log.Println(clientName, "has not connected before?")
				base.ServeHTTP(w, r)
				return
			}

			clientToken := clientCfg.Token.ApiToken

			verified := (clientToken == givenToken)

			log.Debugln("client Token:", clientToken)
			log.Debugln("givenToken:", givenToken)


			if !verified {
				log.WithFields(log.Fields{
					"client": clientName,
					"token":  givenToken,
					"ip":     r.RemoteAddr,
				}).Infoln("Access denied due to invalid token.")

				twirp.WriteError(w, errAccessDenied)

				return
			}

			base.ServeHTTP(w, r)

		*/
	})
}

func getClientName(ctx context.Context) string {
	clientName := ctx.Value(nameCtxKey).(string)
	if clientName != "" {
		return clientName
	}
	return ""
}

func getClientAddress(ctx context.Context) string {
	clientAddr := ctx.Value(addressCtxKey).(string)
	if clientAddr != "" {
		return clientAddr
	}
	return ""
}

func getClientToken(ctx context.Context) string {
	clientToken := ctx.Value(tokenCtxKey).(string)
	if clientToken != "" {
		return clientToken
	}
	return ""
}

func getClientSecret(ctx context.Context) string {
	clientSecret := ctx.Value(secretCtxKey).(string)
	if clientSecret != "" {
		return clientSecret
	}
	return ""
}

// Ping handles the dead-client detection functionality
//
//	It works by spawning a Timer and Ticker for each client
//	- The timer is reset on every successful ping
//	- The ticker triggers the dead-client alerts, once the above timer has expired
func (s *gorramServer) Ping(ctx context.Context, msg *pb.PingMsg) (*pb.PingResponse, error) {
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
	var cfgOutOfDate pb.PingResponse
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
//
//	never cleanly disconnected. If so, an alert is sent,
//	and the LastPingTime is updated.
func (s *gorramServer) reviveDeadClient(clientName string) {
	if s.connectedClients.exists(clientName) {
		s.alert(clientName, &pb.Issue{
			Title:   "Client Revived",
			Message: fmt.Sprintf("%v is alive again!", clientName),
		})
		s.connectedClients.updatePingTime(clientName)
	}
}

func (s *gorramServer) RecordIssue(ctx context.Context, iss *pb.Issue) (*pb.Submitted, error) {
	if iss != nil {
		log.Debugln("recording issue from", getClientName(ctx), iss)
		// Record issue
		s.alert(getClientName(ctx), iss)

		return &pb.Submitted{SuccessfullySubmitted: true}, nil
	}

	return &pb.Submitted{SuccessfullySubmitted: false}, nil
}

func (s *gorramServer) loadClientConfig(client string) (*pb.Config, error) {
	// Attempt to read the config.yml, and then if it has [clientname] in it, unmarshal the config from there
	clientCfg, isThere := s.clientCfgs.Load(client)
	if isThere {
		/*
			if clientCfg == nil {
				return pb.Config{}, errUnknownClient
			}
		*/
		cfg, ok := clientCfg.(*pb.Config)
		if !ok {
			log.Fatalln(cfg, "is not a pb.Config.")
		}
		return cfg, nil
	}

	// Default config values:
	return &pb.Config{}, errUnknownClient
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

func (s *gorramServer) ConfigSync(ctx context.Context, req *pb.ConfigRequest) (*pb.EncryptedConfig, error) {

	clientName := getClientName(ctx)

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

	// Marshal and encrypt the config with the shared secret
	cfgBytes, err := proto.Marshal(cfg)
	if err != nil {
		log.Println("error marshaling config", err)
		return nil, err
	}
	encryptedB := common.Encrypt(s.cfg.SharedSecret, cfgBytes)

	eb := &pb.EncryptedConfig{
		Bytes: encryptedB,
	}

	log.WithFields(log.Fields{
		"client": clientName,
	}).Debugln("Client has synced config.")

	return eb, nil
}

// sendAlert() decides whether to send alerts
// // Uses a very basic cooloff method:
// // - always under 5
// // - less than 50 and divisible by 10
// // - greater than 50 and divisible by 50
// // - greater than 500 and divisible by 100
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

func (s *gorramServer) alert(client string, issue *pb.Issue) {

	// Tie the issue with the given client name here
	issue.Host = client

	// If using alertmanager, submit and exit
	if s.cfg.AlertMethod == "alertmanager" {
		s.addToAlertManager(issue)
		return
	}

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

	} else {
		log.WithFields(log.Fields{
			"client": client,
			"check":  issue.Title,
		}).Debugln("Issue does not exist. Adding to map.", issue.Message)

		a := pb.Alert{
			Issue:         issue,
			TimeSubmitted: time.Now().Unix(),
			TimeLast:      time.Now().Unix(),
			Occurrences:   1,
		}
		s.alertsMap.add(&a)
	}

	//s.alertsMap.mute(generateMapKey(issue))

	log.Debugln("IssueID:", generateMapKey(issue))

	if s.alertsMap.isMuted(issue) {
		log.Debugln("issue is muted. not sending alert")
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
	case "matrix":
		log.WithFields(log.Fields{
			"client": client,
			"check":  issue.Title,
		}).Warnln("[MATRIX ALERT] ", issue.Message)
		s.sendToMatrix(issue)
	}
}

func (s *gorramServer) loadConfig(serverConfFileFullPath, confdFullPath string) {
	//ext := filepath.Ext(confFile)

	// Load server config, from confPath/server.yml, or serverConfFile
	/*
		var serverConfFilePath string
		if serverConfFile != "" {
			serverConfFilePath = serverConfFile
		} else {
			serverConfFilePath = filepath.Join(confPath, "server.yml")
		}
	*/

	serverCfg, err := ioutil.ReadFile(serverConfFileFullPath)
	if err != nil {
		log.Fatalln("Error reading server.yml:", err)
	}

	// Load client configs from conf.d/*.yml
	cfgFiles, err := ioutil.ReadDir(confdFullPath)
	if err != nil {
		log.Fatalln("Error reading configs from conf.d:", err)
	}

	err = yaml.UnmarshalWithOptions(serverCfg, &s.cfg, yaml.Strict())
	if err != nil {
		log.Fatalln("Error unmarshaling server.yml:", err)
	}

	// Check for required AES key
	if s.cfg.SharedSecret == "" {
		log.Fatalln("SharedSecret is required. Must be at least 32 characters.")
	}

	if len(s.cfg.SharedSecret) < 32 {
		log.Fatalln("SharedSecret must be at least 32 characters.")
	}

	for _, cfg := range cfgFiles {
		var newCfg pb.Config
		clientName := strings.TrimSuffix(cfg.Name(), filepath.Ext(cfg.Name()))
		filename := cfg.Name()

		// Only read .yml files
		if filepath.Ext(filename) != ".yml" {
			continue
		}

		fullpath := filepath.Join(confdFullPath, filename)
		newBytes, err := ioutil.ReadFile(fullpath)
		if err != nil {
			log.WithFields(log.Fields{
				"config": fullpath,
				"client": clientName,
			}).Fatalln("Error reading client config", err)
		}
		err = yaml.UnmarshalWithOptions(newBytes, &newCfg, yaml.Strict())
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
		log.Infoln("HeartbeatSeconds is 0, setting to default of 60.")
		s.cfg.HeartbeatSeconds = 60
	}

}

func (s *gorramServer) List(ctx context.Context, qr *pb.QueryRequest) (*pb.ClientList, error) {

	return &s.connectedClients.m, nil
}

func (s *gorramServer) Delete(ctx context.Context, cn *pb.ClientName) (*pb.ClientList, error) {
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

func (s *gorramServer) Debug(ctx context.Context, dr *pb.DebugRequest) (*pb.DebugResponse, error) {

	aString := fmt.Sprintf("Connected clients: %v", &s.connectedClients.m)
	return &pb.DebugResponse{
		Resp: aString,
	}, nil
}

func (s *gorramServer) Hello(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {

	clientName := getClientName(ctx)
	clientAddress := getClientAddress(ctx)

	/*
		// LoginToken should be the shared secret signed with the client's private key
		givenSecret := req.LoginToken

		// On Hello, verify client's key and generate a session token
		// Attempt to load the client's public key from config
		clientPubKey := s.loadClientPubKey(clientName)
		if clientPubKey == "" {
			log.WithFields(log.Fields{
				"client": clientName,
				"secret": givenSecret,
				"ip":     clientAddress,
			}).Debugln("client has no public key configured")
			return nil, errUnknownClient
		}

		clientPubKeyB := common.ParsePublicKey(clientPubKey)

		// Check that the secret key was properly signed by the client
		verified := common.VerifySignature(clientPubKeyB, s.cfg.SharedSecret, givenSecret)

		if !verified {
			log.WithFields(log.Fields{
				"client": clientName,
				"secret": givenSecret,
				"ip":     clientAddress,
			}).Infoln("Access denied due to invalid secret.")

			return nil, errors.New("access denied due to invalid secret")
		}

		log.WithFields(log.Fields{
			"client": clientName,
			"secret": givenSecret,
			"ip":     clientAddress,
		}).Debugln("public key found and signature verified")
	*/

	// Check if the client has connected before
	s.reviveDeadClient(clientName)

	// As this should only be called on client connection, record the client name and address here
	c := &pb.Client{
		Name:         clientName,
		Address:      clientAddress,
		LastPingTime: time.Now().Unix(),
	}

	/*
		t := &pb.Token{
			ApiToken: s.encodeBrancaToken(clientName),
		}

		c.Token = t
	*/
	s.connectedClients.add(c)

	return &pb.LoginResponse{LoggedIn: true}, nil
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
func generateMapKey(i *pb.Issue) string {
	return base64.RawURLEncoding.EncodeToString([]byte(i.Host + i.Title))
}

func (a *alerts) add(alert *pb.Alert) {
	a.Lock()
	if len(a.m) > 20 {
		log.WithFields(log.Fields{
			"client":      alert.Issue.Host,
			"alert":       alert.String(),
			"occurrences": alert.Occurrences,
		}).Debugln("issues map is greater than 20", len(a.m))
	}
	a.m[generateMapKey(alert.Issue)] = alert
	a.Unlock()
}

// count increases the number of occurrences and returns it
//
//	it should only be called in alert(), ensuring the occurrences always increase
//	TimeLast is updated as well, to track stale alerts
func (a *alerts) count(issue *pb.Issue) int64 {
	a.Lock()
	v := a.m[generateMapKey(issue)]
	v.Occurrences = v.Occurrences + 1
	v.TimeLast = time.Now().Unix()
	a.Unlock()
	return v.Occurrences
}

func (a *alerts) exists(issue *pb.Issue) bool {
	a.Lock()
	_, alertExists := a.m[generateMapKey(issue)]
	a.Unlock()
	return alertExists
}

func (a *alerts) get(issue *pb.Issue) *pb.Alert {
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

func (a *alerts) isMuted(issue *pb.Issue) bool {
	var isIt bool
	a.Lock()
	v := a.m[generateMapKey(issue)]
	isIt = v.Muted
	a.Unlock()
	return isIt
}

// expire expires issues that have been stale for 1 hour
func (a *alerts) expire(issue *pb.Issue) {
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

func (c *clients) add(client *pb.Client) {
	c.Lock()
	c.m.Clients[client.Name] = client
	c.Unlock()
}

func (c *clients) exists(clientName string) bool {
	c.Lock()
	_, clientExists := c.m.Clients[clientName]
	c.Unlock()
	return clientExists
}

func (c *clients) get(clientName string) *pb.Client {
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
			s.alert(clientName, &pb.Issue{
				Title:   "Client Offline",
				Message: clientName + " has not connected",
			})
		}

		// Check if connected client hasn't pinged in a while, client interval times 2
		if s.connectedClients.exists(clientName) && s.connectedClients.expired(clientName, clientCfg.Interval) {
			log.Debugln(clientName, "has expired")
			// TODO: should add time they've been offline to the alert
			s.alert(clientName, &pb.Issue{
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

func (s *gorramServer) loadClientPubKey(clientName string) string {
	// try to load the client's public key:
	clientCfg, ok := s.clientCfgs.Load(clientName)
	if !ok {
		log.Debugln("client has no pubkey configured", clientName)
		return ""
	}

	cfg, ok := clientCfg.(*pb.Config)
	if !ok {
		log.Debugln(cfg, "is not a pb.Config.")
		return ""
	}

	log.Debugln("pubkey loaded", clientName, cfg.PublicKey)

	return cfg.PublicKey
}

func (s *gorramServer) verifySharedSecret(givenSecret, clientName string) bool {

	// Verify client's key and generate a session token
	// Attempt to load the client's public key from config
	clientPubKey := s.loadClientPubKey(clientName)
	if clientPubKey == "" {
		log.WithFields(log.Fields{
			"client": clientName,
			"secret": givenSecret,
		}).Debugln("client has no public key configured")
		return false
	}

	clientPubKeyB := common.ParsePublicKey(clientPubKey)

	// Check that the secret key was properly signed by the client
	verified := common.VerifySignature(clientPubKeyB, s.cfg.SharedSecret, givenSecret)

	if !verified {
		log.WithFields(log.Fields{
			"client": clientName,
			"secret": givenSecret,
		}).Infoln("Access denied due to invalid secret.")

		return false
	}

	log.WithFields(log.Fields{
		"client": clientName,
		"secret": givenSecret,
	}).Debugln("public key found and signature verified")

	return verified
}

func main() {

	formatter := new(log.TextFormatter)
	formatter.TimestampFormat = "01-02-2006 03:04:05pm"
	formatter.FullTimestamp = true
	formatter.DisableLevelTruncation = true
	log.SetFormatter(formatter)

	// Set config via flags
	confPath := flag.String("conf", "/etc/gorram/", "Path where server.yml and a conf.d directory (for client configs) are stored.")
	//insecure := flag.Bool("insecure", false, "Disable TLS. Allow insecure client connections.")
	generateCAcert := flag.Bool("generate-ca", false, "Generate CA certificates, at cacert.pem and cacert.key.")
	//sslPath := flag.String("ssl-path", "/etc/gorram/", "Path to read/write SSL certs from.")
	//sslCert := flag.String("ssl-cert-path", "/etc/gorram/server.pem", "Path to read exact SSL cert from (for LetsEncrypt, etc).")
	//sslCertKey := flag.String("ssl-cert-path", "/etc/gorram/server.key", "Path to read exact SSL key from (for LetsEncrypt, etc).")
	debug := flag.Bool("debug", false, "Toggle debug logging.")
	showVersion := flag.Bool("version", false, "Print server version")
	serverConfFile := flag.String("conf-file", "", "Direct path to server.yml, if outside the SSL and client configs.")
	//serverAddress := flag.String("listen-address", "127.0.0.1:50000", "Address and port to listen on.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the server certificate.")
	//serverCertKey := flag.String("key", "cert.key", "Path to the server certificate key.")
	//secret := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//alertMethodF := flag.String("alert", "log", "Alert method to use. Right now, log. To come: pushover.")
	flag.Parse()

	// Setup full paths to server and client config files
	var serverCfg string
	if *serverConfFile != "" {
		serverCfg = *serverConfFile
	} else {
		serverCfg = filepath.Join(*confPath, "server.yml")
	}
	//serverCfg := filepath.Join(*confPath, "server.yml")
	clientConfd := filepath.Join(*confPath, "conf.d")

	if *showVersion {
		log.Printf("Build date: %s\nGit commit: %s\n", buildTime, sha1ver)
		os.Exit(0)
	}

	// Set debug from flag here to allow debugging config loading and cert generation
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	gs := gorramServer{
		cfg:              serverConfig{},
		clientCfgs:       *new(sync.Map),
		connectedClients: *new(clients),
	}

	gs.loadConfig(serverCfg, clientConfd)

	if gs.cfg.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if *generateCAcert {
		log.Infoln("Generating cacert.pem and cacert.key...")
		certs.GenerateCACert(*&gs.cfg.SSLPath)
	}

	/*
		// TLS stuff
		var creds tls.Config

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
				if gs.cfg.TLSHostnames == nil {
					log.Fatalln("Error: Unable to dynamically generate server cert with blank hostname. Please configure 'TLSHostname' in server config.")
				}
				// Generate certificates dynamically:
				log.Debugln("Generating certificate dynamically for", gs.cfg.TLSHostnames)
				tlsCert = certs.GenerateServerCert(gs.cfg.TLSHostnames, *sslPath)
			}

			caCert, err := ioutil.ReadFile(caCertPath)
			if err != nil {
				log.Fatalln("Error reading", caCertPath, err)
			}
			certPool := x509.NewCertPool()
			if success := certPool.AppendCertsFromPEM(caCert); !success {
				log.Fatalln("Cannot append certs from PEM to certpool.")
			}

			creds = tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{tlsCert},
				ClientCAs:    certPool,
			}

		}
	*/

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	gs.alertsMap.m = make(map[string]*pb.Alert)

	gs.connectedClients.m.Clients = make(map[string]*pb.Client)

	// Watch for config.yml changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalln("Error watching config file for changes:", err)
	}

	// Setup servers
	reportHandler := pb.NewReporterServer(&gs)
	queryHandler := pb.NewQuerierServer(&gs)

	mux := http.NewServeMux()
	mux.Handle(reportHandler.PathPrefix(), WithClientName(gs.Authorize(reportHandler)))
	mux.Handle(queryHandler.PathPrefix(), WithClientName(gs.Authorize(queryHandler)))

	// Start listening, in a goroutine so SIGINTs can be caught below
	go func() {
		//err := http.ListenAndServe(gs.cfg.ListenAddress, mux)
		err := http.ListenAndServeTLS(gs.cfg.ListenAddress, gs.cfg.SSLCertPath, gs.cfg.SSLKeyPath, mux)
		log.Infoln("Listening on", gs.cfg.ListenAddress)

		if err != nil {
			log.Fatalf("Failed to start Gorram server: %v", err)
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
					gs.loadConfig(serverCfg, clientConfd)
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
	err = watcher.Add(serverCfg)
	if err != nil {
		log.Fatalln("Error watching server.yml:", err)
	}
	err = watcher.Add(clientConfd)
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
}
