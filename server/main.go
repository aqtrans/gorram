package main

import (
	"context"
	"errors"
	"flag"

	//"log"

	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"maunium.net/go/mautrix"

	_ "net/http/pprof"

	_ "github.com/mattn/go-sqlite3"
	_ "github.com/tevjef/go-runtime-metrics/expvar"

	"git.jba.io/go/gorram/certs"
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
	matrixbot        *mautrix.Client
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
		certs.GenerateCACert(gs.cfg.SSLPath)
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

	// Spin up a Matrix bot to send alerts if necessary:
	if gs.cfg.AlertMethod == "matrix" {
		gs.setupMatrixClient()
		// Give Matrix bot 10 seconds to spin up
		//time.Sleep(10 * time.Second)
		if gs.matrixbot == (&mautrix.Client{}) {
			log.Errorln("Matrix Client is empty")
			return
		}
		//log.Println("Matrix Room ID: " + gs.matrixbot.UserID.URI().RoomID())
	}

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
