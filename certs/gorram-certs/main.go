package main

import (
	"flag"
	"git.jba.io/go/gorram/certs"
	"log"
	"os"
)

func main() {

	// Set config via flags
	//serverCert := flag.String("cert", "server.pem", "Path to the server certificate.")
	//serverCertKey := flag.String("key", "server.key", "Path to the server certificate key.")
	generateServer := flag.Bool("server", false, "Generate server certs if given.")
	generateHost := flag.String("host", "127.0.0.1", "If generate-certs is specified, override the host in the cert.")
	generateClient := flag.Bool("client", false, "Generate client certs if given.")
	generateCA := flag.Bool("ca", false, "Generate CA cert if given.")

	flag.Parse()

	if *generateCA {
		certs.GenerateCACert()
	}

	if *generateServer {
		// Only generate cert.pem if it do not exist
		if _, err := os.Stat("server.pem"); err == nil {
			log.Fatalln("server.pem already exists. Not overwriting. Manually remove it and cert.key if you need to re-generate them.")
		}
		log.Println("Generating", *generateHost, "certs to server.pem and server.key")
		certs.SaveServerCert(*generateHost, "cacert.pem", "cacert.key")
	}

	if *generateClient {
		clientCert := *generateHost + ".pem"
		clientKey := *generateHost + ".key"
		// Only generate cert.pem if it do not exist
		if _, err := os.Stat(clientCert); err == nil {
			log.Fatalln(clientCert, "already exists. Not overwriting. Manually remove it and cert.key if you need to re-generate them.")
		}
		log.Println("Generating certs to", clientCert, "and", clientKey)
		certs.SaveClientCert(*generateHost, "cacert.pem", "cacert.key")
	}

}
