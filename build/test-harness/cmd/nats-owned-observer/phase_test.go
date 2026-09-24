package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestFailedConnectionReportsOnlySafePhaseCode(t *testing.T) {
	binary := observerBinary(t)
	cfg := randomConfig(t)
	cfg.BrokerURL = "nats://localhost:1"
	cfg.AllowedServerIDs = []string{"PINNED_SERVER_ID"}
	cfg.ExpectedPayloadSHA256 = strings.Repeat("0", 64)
	cfg.ConnectTimeoutMillis = 100
	output, err := exec.Command(binary, "--config", writeConfig(t, cfg)).CombinedOutput()
	if err == nil || string(output) != "observer: CONNECT_FAILED\n" {
		t.Fatalf("unbounded or missing phase diagnostic: err=%v output=%q", err, output)
	}
}
