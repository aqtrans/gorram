package main

import (
	"context"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"git.jba.io/go/gorram/checks"
	"git.jba.io/go/gorram/common"
	"git.jba.io/go/gorram/proto"

	log "github.com/sirupsen/logrus"
	"github.com/twitchtv/twirp"
	"gopkg.in/yaml.v2"
)

var (
	sha1ver   string // git commit to be set when built
	buildTime string // date+time to be set when built
)

type clientConfig struct {
	ClientName    string `yaml:"name,omitempty"`
	ServerSecret  string `yaml:"secret_key,omitempty"`
	ServerAddress string `yaml:"server_address,omitempty"`
	PrivateKey    string `yaml:"private_key,omitempty"`
}

func loadConfig(confFile string) clientConfig {
	var cfg clientConfig
	// Load client.yml here
	cfgBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		log.Fatalln("Error reading confFile:", err)
	}

	err = yaml.Unmarshal(cfgBytes, &cfg)
	if err != nil {
		log.Fatalln("Error unmarshaling confFile:", err)
	}

	return cfg
}

// newCtx creates timeout contexts, with the proper stuff in headers
func newCtx(header http.Header, timeout time.Duration) (context.Context, context.CancelFunc) {
	// Attach the Twirp headers to a context
	ctx := context.Background()
	ctx, err := twirp.WithHTTPRequestHeaders(ctx, header)
	if err != nil {
		log.Printf("twirp error setting headers: %s", err)
		return context.Background(), nil
	}

	return context.WithTimeout(ctx, timeout)
}

func main() {

	formatter := new(log.TextFormatter)
	formatter.TimestampFormat = "01-02-2006 03:04:05pm"
	formatter.FullTimestamp = true
	formatter.DisableLevelTruncation = true
	log.SetFormatter(formatter)

	// Set config via flags
	confFile := flag.String("conf", "client.yml", "Path to the YAML config file.")
	generateKeys := flag.Bool("generate-keys", false, "Generate base64-encoded ed25519 keys and print them to terminal")
	//sslPath := flag.String("ssl-path", "/etc/gorram/", "Path to read/write SSL certs from.")
	//clientName := flag.String("name", "unnamed", "Name of the client, as seen by the server. Should be unique.")
	//serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	//insecure := flag.Bool("insecure", false, "Connect to server without TLS.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the certificate from the server.")
	//secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")
	debug := flag.Bool("debug", false, "Toggle debug logging.")
	showVersion := flag.Bool("version", false, "Print server version")
	flag.Parse()

	if *showVersion {
		log.Printf("Build date: %s\nGit commit: %s\n", buildTime, sha1ver)
		os.Exit(0)
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if *generateKeys {
		pubKey, privKey := common.GenerateKeys()
		log.Println(`New keys generated. Paste public key into server's $clientname.yml, and private key into client.yml`)
		log.Println("Private key:", privKey)
		log.Println("Public key:", pubKey)
		os.Exit(0)
	}

	// Set a global RPC timeout, to be used in context.WithTimeout()'s alongside each RPC call
	rpcTimeout := 180 * time.Second

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	yamlCfg := loadConfig(*confFile)

	/* Trying to send client-name as early as possible...
		Doesn't seem to send on the Dial
	// Metadata
	md := metadata.New(map[string]string{
		"client": "client1",
		"secret": *secretKey,
	})
	err := grpc.SetHeader(ctx, md)
	*/

	// Set up a connection to the server.

	c := proto.NewReporterProtobufClient(yamlCfg.ServerAddress, &http.Client{})

	/*
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalln("error generating ed25519 keys", err)
		}
		log.Println(pub, priv)
		pubEnc := base64.URLEncoding.EncodeToString(pub)
		privEnc := base64.URLEncoding.EncodeToString(priv)
		err = ioutil.WriteFile("homer.pub", []byte(pubEnc), 0644)
		if err != nil {
			log.Fatalln("error writing pub key", err)
		}
		err = ioutil.WriteFile("homer.key", []byte(privEnc), 0644)
		if err != nil {
			log.Fatalln("error writing priv key", err)
		}
		os.Exit(0)
	*/

	/* Sign the shared secret using ed25519 with our private key
	   The server will use our public key to verify it */
	privkeyB := common.ParsePrivateKey(yamlCfg.PrivateKey)
	encryptedSecret := common.SignSignature(privkeyB, yamlCfg.ServerSecret)

	log.Debugln("server secret encrypted with private key:", encryptedSecret)

	// Given some headers ...
	header := make(http.Header)
	header.Set("Gorram-Secret", encryptedSecret)
	header.Set("Gorram-Client-ID", yamlCfg.ClientName)

	// Create RPC context, add client name metadata
	rpcCtx, rpcCancel := newCtx(header, rpcTimeout)

	// Hello: Get config from server, and ensure dead tickers are stopped
	origCfg, err := c.Hello(rpcCtx, &proto.ConfigRequest{
		ClientName: yamlCfg.ClientName,
	})
	if err != nil {
		log.Fatalln("Error with c.Hello:", err)
	}
	rpcCancel()

	log.Println("Client successfully connected to server.")

	cfgMutex := &sync.Mutex{}

	// Ping and collect issues every X seconds
	ticker := time.NewTicker(time.Duration(origCfg.Interval) * time.Second)
	//cfgChan := make(chan *gorram.Config)

	go func() {
		for {
			select {
			case <-ticker.C:

				cfgMutex.Lock()
				rpcCtx, rpcCancel := newCtx(header, rpcTimeout)
				defer rpcCancel()
				pingResp, err := c.Ping(rpcCtx, &proto.PingMsg{IsAlive: true, CfgLastUpdated: origCfg.LastUpdated})
				if err != nil {
					log.Fatalln("Error with c.Ping:", err)
				}
				// This variable should be true if the config is out of sync
				if pingResp.CfgOutOfSync {
					// Fetch and set the new config
					log.Debugln("Configuration out of sync. Fetching new config from server.")
					var err error

					rpcCtx, rpcCancel := newCtx(header, rpcTimeout)
					defer rpcCancel()
					newCfg, err := c.ConfigSync(rpcCtx, &proto.ConfigRequest{
						ClientName: yamlCfg.ClientName,
					})
					if err != nil {
						log.Fatalln("Error with c.ConfigSync:", err)
					}
					// Set cfg to newCfg
					origCfg = newCfg
				}
				// Send config, either the new or old, through the channel
				//cfgChan <- origCfg
				cfgMutex.Unlock()
				//close(cfgChan)

				//cfg2 := <-cfgChan

				// Do checks
				i := checks.DoChecks(origCfg)
				// If there are any checks, open a client-side stream and record them
				if len(i) > 0 {

					for _, issue := range i {

						rpcCtx, rpcCancel := newCtx(header, rpcTimeout)
						defer rpcCancel()
						problem, err := c.RecordIssue(rpcCtx, issue)
						if err != nil {
							log.Fatalln("Error recording issue:", i, err)
						}
						if !problem.SuccessfullySubmitted {
							log.Fatalln("Error submitting issue; Check server logs.", problem.SuccessfullySubmitted)
						}
					}
				}
				log.Debugln("Number of Goroutines:", runtime.NumGoroutine())
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	go func() {
		sig := <-sigs
		log.Warnln("Signal caught", sig)
		done <- true
	}()

	<-done
	log.Println("Client exiting...")
	rpcCancel()
	ticker.Stop()

}
