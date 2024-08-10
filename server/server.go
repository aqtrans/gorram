package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"git.sr.ht/~aqtrans/gorram/common"
	pb "git.sr.ht/~aqtrans/gorram/proto"
	"github.com/goccy/go-yaml"
	"github.com/gregdel/pushover"
	log "github.com/sirupsen/logrus"
	"github.com/twitchtv/twirp"
	"google.golang.org/protobuf/proto"
)

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
		// Send alert itself to Matrix room
		err := s.sendToMatrix(issue)
		if err != nil {
			log.Errorln("error sending alert to Matrix:", err)
			return
		}
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
