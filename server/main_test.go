package main

import (
	"context"
	"testing"

	gorram "git.sr.ht/~aqtrans/gorram/proto"
)

var clientName = "testClient"

func testCtx() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, nameCtxKey, clientName)
	ctx = context.WithValue(ctx, addressCtxKey, "1.2.3.4")
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

	s.reviveDeadClient(clientName)

}

func TestAlerts(t *testing.T) {
	iss := gorram.Issue{
		Host:    "omg",
		Title:   "title",
		Message: "omg",
	}
	s := &gorramServer{}
	s.alertsMap.m = make(map[string]*gorram.Alert)

	s.cfg.AlertMethod = "log"
	for i := 1; i < 100; i++ {
		s.alert("omg", &iss)
	}
}

/*
// TestConfig tests that all supported config formats are equal
func TestConfig(t *testing.T) {
	tomlServer := &gorramServer{}
	yamlServer := &gorramServer{}
	hclServer := &gorramServer{}
	tomlServer.loadConfig("tests/testcfg.toml")
	yamlServer.loadConfig("tests/testcfg.yaml")
	hclServer.loadConfig("tests/testcfg.hcl")
	if !reflect.DeepEqual(yamlServer.cfg, tomlServer.cfg) {
		t.Fatal("YAML and TOML server configs do not match:", yamlServer.cfg, tomlServer.cfg)
	}
	if !reflect.DeepEqual(hclServer.cfg, tomlServer.cfg) {
		t.Fatal("HCL and TOML server configs do not match:", hclServer.cfg, tomlServer.cfg)
	}
	if !reflect.DeepEqual(hclServer.cfg, yamlServer.cfg) {
		t.Fatal("HCL and YAML server configs do not match:", hclServer.cfg, yamlServer.cfg)
	}
	//t.Log("YAML", yamlServer.cfg)
	//t.Log("TOML", tomlServer.cfg)
	//t.Log("HCL", hclServer.cfg)
	// Run through pre-defined client names client1, client2, client3
	for i := 1; i < 4; i++ {
		clientName := "client" + strconv.Itoa(i)
		tomlcfg, err := tomlServer.loadClientConfig(clientName)
		if err != nil {
			t.Fatal(err)
		}
		yamlcfg, err := yamlServer.loadClientConfig(clientName)
		if err != nil {
			t.Fatal(err)
		}
		hclcfg, err := hclServer.loadClientConfig(clientName)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(tomlcfg, yamlcfg) {
			t.Log("TestConfig error: ", clientName, "YAML config does not match TOML:")
			t.Log("TOML:", tomlcfg)
			t.Log("YAML:", yamlcfg)
			t.Fail()
		}

		if !reflect.DeepEqual(tomlcfg, hclcfg) {
			t.Log("TestConfig error: ", clientName, "HCL config does not match TOML:")
			t.Log("TOML:", tomlcfg)
			t.Log("HCL:", hclcfg)
			t.Fail()
		}

		if !reflect.DeepEqual(yamlcfg, hclcfg) {
			t.Log("TestConfig error: ", clientName, "HCL config does not match YAML:")
			t.Log("YAML:", yamlcfg)
			t.Log("HCL:", hclcfg)
			t.Fail()
		}

	}
}
*/
