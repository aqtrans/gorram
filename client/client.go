package main

import (
	"context"
	"io"
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

	ping, err := c.Ping(ctx, &gorram.PingMessage{ClientName: "omg", IsAlive: true})
	if err != nil {
		log.Println(err)
	}
	log.Println(ping.GetIsAlive())

	issueStream, err := c.RecordIssue(ctx)
	if err != nil {
		log.Println(err)
	}

	waitc := make(chan struct{})
	go func() {
		for {
			var b gorram.Submitted
			err := issueStream.RecvMsg(&b)
			if err == io.EOF {
				close(waitc)
				return
			}
			if err != nil {
				log.Println(err)
			}
			log.Println("Server sent", b)
		}
	}()
	err = issueStream.Send(&gorram.Issue{
		ClientName: "omg",
		Message:    "woooo",
	})
	if err != nil {
		log.Println(err)
	}
	err = issueStream.CloseSend()
	if err != nil {
		log.Println(err)
	}
	<-waitc
}
