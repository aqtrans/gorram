package main

import (
	"context"
	"reflect"
	"strconv"
	"testing"
	"time"

	gorram "git.jba.io/go/gorram/proto"
	"google.golang.org/grpc/metadata"
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

// TestConfig tests that all supported config formats are equal
func TestConfig(t *testing.T) {
	tomlServer := &gorramServer{}
	yamlServer := &gorramServer{}
	//hclServer := &gorramServer{}
	tomlServer.loadConfig("tests/testcfg.toml")
	yamlServer.loadConfig("tests/testcfg.yaml")
	//hclServer.loadConfig("tests/testcfg.hcl")
	if !reflect.DeepEqual(yamlServer.cfg, tomlServer.cfg) {
		t.Fatal("YAML and TOML server configs do not match:", yamlServer.cfg, tomlServer.cfg)
	}
	//t.Log("YAML", yamlServer.cfg)
	//t.Log("TOML", tomlServer.cfg)
	//t.Log("HCL", hclServer.cfg)
	// Run through pre-defined client names client1, client2, client3
	for i := 1; i < 4; i++ {
		clientName := "client" + strconv.Itoa(i)
		tomlcfg := tomlServer.loadClientConfig(clientName)
		yamlcfg := yamlServer.loadClientConfig(clientName)
		//hclcfg := hclServer.loadClientConfig(clientName)
		if !reflect.DeepEqual(tomlcfg, yamlcfg) {
			t.Log("TestConfig error: ", clientName, "YAML config does not match TOML:")
			t.Log("TOML:", tomlcfg)
			t.Log("YAML:", yamlcfg)
			t.Fail()
		}
		/*
			if !reflect.DeepEqual(tomlcfg, hclcfg) {
				t.Log("TestConfig error: ", clientName, "HCL config does not match TOML:")
				t.Log("TOML:", tomlcfg)
				t.Log("HCL:", hclcfg)
				t.Fail()
			}
		*/
	}
}
