package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"jba.io/go/gorram/proto"
)

type secret struct {
	Secret string
	TLS    bool
}

func (s *secret) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	//log.Println(uri, ctx)
	return map[string]string{
		"secret": s.Secret,
	}, nil
}

func (s *secret) RequireTransportSecurity() bool {
	return s.TLS
}

func main() {
	// Set config via flags
	serverAddress := flag.String("server-address", "127.0.0.1:50000", "Address and port of the server.")
	insecure := flag.Bool("insecure", false, "Connect to server without TLS.")
	serverCert := flag.String("cert", "cert.pem", "Path to the certificate from the server.")
	secretKey := flag.String("server-secret", "omg12345", "Secret key of the server.")
	//interval := flag.Duration("interval", 60*time.Second, "Number of seconds to check for issues on.")

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	var conn *grpc.ClientConn
	var err error
	var creds credentials.TransportCredentials
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	if *insecure {
		conn, err = grpc.DialContext(dialCtx, *serverAddress, grpc.WithBlock(), grpc.WithInsecure(), grpc.WithPerRPCCredentials(&secret{
			Secret: *secretKey,
			TLS:    false,
		}))
	} else {
		creds, err = credentials.NewClientTLSFromFile(*serverCert, "")
		if err != nil {
			log.Fatal("Error parsing TLS cert:", err)
		}
		conn, err = grpc.DialContext(dialCtx, *serverAddress, grpc.WithBlock(), grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(&secret{
			Secret: *secretKey,
			TLS:    true,
		}))
	}
	if err != nil {
		log.Printf("Error connecting to server: %v", err)
		return
	}

	c := gorram.NewQuerierClient(conn)

	cl, err := c.List(ctx, &gorram.QueryRequest{
		TimeSubmitted: time.Now().Unix(),
	})
	if err != nil {
		log.Println(err)
	}
	log.Println(cl.Clients)

	cancel()
	err = conn.Close()
	if err != nil {
		log.Println("Error closing connection:", err)
	}
}
