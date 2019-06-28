package main

import (
	"context"
	"git.jba.io/go/gorram/proto"
	"google.golang.org/grpc/metadata"
	"testing"
	"time"
)

var clientName = "testClient"

func testCtx() context.Context {
	md := metadata.New(map[string]string{"client": clientName})
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, md)
	return ctx
}

func TestGetClientName(t *testing.T) {
	ctx := testCtx()

	respClientName := getClientName(ctx)
	if respClientName != clientName {
		t.Errorf("TestGetClientName returned %v. Expected: %v", respClientName, clientName)
	}
}

func TestPing(t *testing.T) {
	ctx := testCtx()
	s := &gorramServer{}

	s.clientCfgs.Store(clientName, &gorram.Config{
		LastUpdated: 1,
		Interval:    60,
	})

	msg := &gorram.PingMsg{
		IsAlive:        true,
		CfgLastUpdated: 1,
	}

	_, err := s.Ping(ctx, msg)
	if err != nil {
		t.Errorf("PingTest error: %v", err)
	}
}

func TestReviveDeadClient(t *testing.T) {
	//ctx := testCtx()
	s := &gorramServer{}
	s.alertsMap.m = make(map[string]*gorram.Alert)

	// Create and store new ticker
	ticker := time.NewTicker(60 * time.Second)
	s.clientTimers.tickers.Store(clientName, ticker)

	s.reviveDeadClient(clientName)

}
