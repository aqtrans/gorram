package main

import (
	"context"
	"errors"
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
	pb "git.jba.io/go/gorram/proto"
	"google.golang.org/protobuf/proto"

	"github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/twitchtv/twirp"

	_ "net/http/pprof"
)

var (
	sha1ver   string // git commit to be set when built
	buildTime string // date+time to be set when built
)

type clientConfig struct {
	ClientName    string `yaml:"name,omitempty"`
	SharedSecret  string `yaml:"shared_secret,omitempty"`
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

	err = yaml.UnmarshalWithOptions(cfgBytes, &cfg, yaml.Strict())
	if err != nil {
		log.Fatalln("Error unmarshaling confFile:", err)
	}

	// Check for required AES key
	if cfg.SharedSecret == "" {
		log.Fatalln("SharedSecret is required. Must be at least 32 characters.")
	}

	if len(cfg.SharedSecret) < 32 {
		log.Fatalln("SharedSecret must be at least 32 characters.")
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

func decryptCfg(sharedSecret string, encryptedConfig *pb.EncryptedConfig) *pb.Config {
	decryptedBytes := common.Decrypt(sharedSecret, encryptedConfig.Bytes)
	origCfg := &pb.Config{}
	err := proto.Unmarshal(decryptedBytes, origCfg)
	if err != nil {
		log.Fatalln("unable to unmarshal config:", err)
	}
	return origCfg
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
		//log.Println("AES shared secret:", aesKey)
		os.Exit(0)
	}

	// Set a global RPC timeout, to be used in context.WithTimeout()'s alongside each RPC call
	rpcTimeout := 180 * time.Second

	// Catch Ctrl+C, sigint
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		log.Warnln("Signal caught", sig)
		done <- true
		log.Println("Client exiting...")
		os.Exit(1)
	}()

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

	c := pb.NewReporterProtobufClient(yamlCfg.ServerAddress, &http.Client{})

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
	encryptedSecret := common.SignSignature(privkeyB, yamlCfg.SharedSecret)

	log.Debugln("server secret encrypted with private key:", encryptedSecret)

	header := make(http.Header)
	// Add client name and encrypted secret to headers
	header.Set("Gorram-Secret", encryptedSecret)
	header.Set("Gorram-Client-ID", yamlCfg.ClientName)

	// Create RPC context, add client name metadata
	rpcCtx, rpcCancel := newCtx(header, rpcTimeout)

	retryConnection := true

	for retryConnection {
		// Hello: Get a LoginToken from the server, if our signature is verified by the server
		isLoggedIn, err := c.Hello(rpcCtx, &pb.LoginRequest{
			LoginTime: time.Now().Unix(),
		})

		if err != nil {
			if twerr, ok := err.(twirp.Error); ok {
				if twerr.Code() == twirp.Internal {
					if transportErr := errors.Unwrap(twerr); transportErr != nil {
						// transportErr could be something like an HTTP connection error
						//log.Println(transportErr.Error())
						/*
							var netError *net.OpError
							if errors.As(err, &netError) {
								if netError.Op == "dial" {
									log.Println("Unknown host")
								} else if netError.Op == "read" {
									log.Println("Connection refused")
								}
							}
						*/

						var sysErr syscall.Errno
						if errors.As(err, &sysErr) {
							if sysErr == syscall.ECONNREFUSED {
								log.Println("Connection refused")
								retryConnection = true
							}
						}

					}
				}
			}
			log.Println("Error with c.Hello:", err)
			time.Sleep(10 * time.Second)
		}

		if isLoggedIn != nil && isLoggedIn.LoggedIn {
			log.Println("logged in to the server!")
			retryConnection = false
		}

	}

	rpcCancel()

	// Add token to the headers and context
	//header.Set("Gorram-Token", apiToken.ApiToken)
	rpcCtx, rpcCancel = newCtx(header, rpcTimeout)

	encryptedBytes, err := c.ConfigSync(rpcCtx, &pb.ConfigRequest{
		ClientName: yamlCfg.ClientName,
	})
	if err != nil {
		log.Fatalln("Error with c.ConfigSync:", err)
	}

	origCfg := decryptCfg(yamlCfg.SharedSecret, encryptedBytes)

	log.Println("Client successfully connected to server.")

	cfgMutex := &sync.Mutex{}

	// Ping and collect issues every X seconds
	ticker := time.NewTicker(time.Duration(origCfg.Interval) * time.Second)
	//cfgChan := make(chan *gorram.Config)

	go func() {
		for {
			select {
			case <-ticker.C:

				cfgChan := make(chan *pb.Config)

				go func() {
					cfgMutex.Lock()
					rpcCtx, rpcCancel := newCtx(header, rpcTimeout)
					defer rpcCancel()
					pingResp, err := c.Ping(rpcCtx, &pb.PingMsg{IsAlive: true, CfgLastUpdated: origCfg.LastUpdated})
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
						newCfgEnc, err := c.ConfigSync(rpcCtx, &pb.ConfigRequest{
							ClientName: yamlCfg.ClientName,
						})
						if err != nil {
							log.Fatalln("Error with c.ConfigSync:", err)
						}
						newCfg := decryptCfg(yamlCfg.SharedSecret, newCfgEnc)
						// Set cfg to newCfg
						origCfg = newCfg
					}
					// Send config, either the new or old, through the channel
					//cfgChan <- origCfg
					cfgMutex.Unlock()
					//close(cfgChan)

					cfgChan <- origCfg

					//cfg2 := <-cfgChan
				}()

				go func() {

					origCfg = <-cfgChan

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
				}()

				log.Debugln("Number of Goroutines:", runtime.NumGoroutine())
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	// Expose expvars and pprof on http://127.0.0.1:50002
	go func() {
		if err := http.ListenAndServe("127.0.0.1:50002", nil); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-done
	log.Println("Client exiting...")
	rpcCancel()
	ticker.Stop()

}
