package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"jba.io/go/gorram/gorram"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial("127.0.0.1:50000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	//c := pb.NewGreeterClient(conn)
	c := gorram.NewReporterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ping, err := c.Ping(ctx, &gorram.PingMessage{Alive: true})
	if err != nil {
		log.Println(err)
	}
	log.Println(ping.GetAlive())
}
