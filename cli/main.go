package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/aqtrans/gorram/proto"
	"github.com/twitchtv/twirp"
)

func main() {
	// Set config via flags
	serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	//insecure := flag.Bool("insecure", false, "Connect to server without TLS.")
	//serverCert := flag.String("cert", "cert.pem", "Path to the certificate from the server.")
	secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")
	list := flag.Bool("list", false, "List connected clients and exit.")
	deleteClient := flag.String("delete", "", "Delete named client and stop it's ticker.")
	debug := flag.Bool("debug", false, "List debugging info and exit.")

	flag.Parse()

	// Given some headers ...
	header := make(http.Header)
	header.Set("Gorram-Secret", *secretKey)
	header.Set("Gorram-Client-ID", "gorram-cli")

	// Attach the Twirp headers to a context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, err := twirp.WithHTTPRequestHeaders(ctx, header)
	if err != nil {
		log.Printf("twirp error setting headers: %s", err)
	}

	c := proto.NewQuerierProtobufClient(*serverAddress, &http.Client{})

	if *list {
		cl, err := c.List(ctx, &proto.QueryRequest{
			TimeSubmitted: time.Now().Unix(),
		})
		if err != nil {
			log.Println(err)
		}
		log.Println(cl.Clients)
	}
	if *deleteClient != "" {
		cl, err := c.Delete(ctx, &proto.ClientName{
			Name: *deleteClient,
		})
		if err != nil {
			log.Println(err)
		}
		log.Println(cl.Clients)
	}
	if *debug {
		cl, err := c.Debug(ctx, &proto.DebugRequest{
			Debug: true,
		})
		if err != nil {
			log.Println(err)
		}
		log.Println(cl.String())
	}

	cancel()

}
