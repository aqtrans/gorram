package main

import (
	"context"
	"io"
	"log"

	"google.golang.org/grpc"
	"jba.io/go/gorram/gorram"
)

func reportIssues() []*gorram.Issue {
	issue1 := &gorram.Issue{
		ClientName: "omg",
		Message:    "woooo",
	}
	issue2 := &gorram.Issue{
		ClientName: "omg",
		Message:    "woooo1",
	}
	issue3 := &gorram.Issue{
		ClientName: "omg",
		Message:    "woooo2",
	}
	return []*gorram.Issue{issue1, issue2, issue3}
}

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ping, err := c.Ping(ctx, &gorram.PingMessage{ClientName: "omg", IsAlive: true})
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(ping.GetIsAlive())

	issueStream, err := c.RecordIssue(ctx)
	if err != nil {
		log.Fatalln(err)
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
				log.Fatalln("err receiving message back from server:", err)
			}
			log.Println("Server sent", b)
		}
	}()

	i := reportIssues()

	for _, issue := range i {
		err = issueStream.Send(issue)
		log.Println(issue.Message)
		if err != nil {
			log.Fatalln("omg", err)
		}
	}
	err = issueStream.CloseSend()
	if err != nil {
		log.Println(err)
	}

	<-waitc
}
