package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
)

// standaloneNATSServer serves the pinned NATS version on 127.0.0.1 only and
// returns a hostname URL, so the observer subprocess must resolve and pin the
// address itself. The server runs in-process from the module's own dependency;
// building the nats-server main package would need modules go.sum does not pin.
func standaloneNATSServer(t *testing.T) (string, string) {
	t.Helper()
	if server.VERSION != "2.10.29" {
		t.Fatalf("NATS server version=%s, want 2.10.29", server.VERSION)
	}
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("standalone local NATS did not become ready")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	return fmt.Sprintf("nats://localhost:%d", srv.Addr().(*net.TCPAddr).Port), srv.ID()
}

func TestHostnameURLUsesPinnedAddressBeforeSubscription(t *testing.T) {
	brokerURL, id := standaloneNATSServer(t)
	binary := observerBinary(t)
	cfg := randomConfig(t)
	cfg.BrokerURL = brokerURL
	cfg.AllowedServerIDs = []string{id}
	cfg.ExpectedPayloadSHA256 = strings.Repeat("0", 64)
	path := writeConfig(t, cfg)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--config", path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		readErr := scanner.Err()
		waitErr := command.Wait()
		t.Fatalf("hostname connection emitted no subscription receipt; wait=%v stderr=%q read=%v", waitErr, stderr.String(), readErr)
	}
	var handshake receipt
	if err := json.Unmarshal(scanner.Bytes(), &handshake); err != nil {
		t.Fatal(err)
	}
	if handshake.Kind != "subscription" || handshake.Status != "READY" || !handshake.Flushed || handshake.ServerID != id {
		t.Fatalf("wrong hostname handshake: %+v", handshake)
	}
	if !scanner.Scan() {
		t.Fatalf("missing bounded observation: %q", stderr.String())
	}
	var observation receipt
	if err := json.Unmarshal(scanner.Bytes(), &observation); err != nil {
		t.Fatal(err)
	}
	if observation.Status != "TIMEOUT_UNKNOWN" {
		t.Fatalf("unexpected no-publication observation: %+v", observation)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("observer hostname run failed: %v: %q", err, stderr.String())
	}
}

func TestFixedDialerRejectsAlternateAddress(t *testing.T) {
	d := fixedDialer{address: "localhost:4222", timeout: time.Second}
	if _, err := d.Dial("tcp", "127.0.0.1:4222"); err == nil {
		t.Fatal("alternate resolved address was accepted")
	}
}
