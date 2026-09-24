package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func standaloneNATSServer(t *testing.T) (string, string) {
	t.Helper()
	serverBinary := filepath.Join(t.TempDir(), "nats-server-2.10.29")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", serverBinary, "github.com/nats-io/nats-server/v2")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOMAXPROCS=1", "GOFLAGS=-p=1")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build pinned local server: %v: %s", err, output)
	}
	version, err := exec.Command(serverBinary, "-v").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "v2.10.29") {
		t.Fatalf("local NATS server version differs: err=%v version=%q", err, version)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, serverBinary, "-a", "127.0.0.1", "-p", fmt.Sprint(port))
	var logs bytes.Buffer
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	address := fmt.Sprintf("nats://127.0.0.1:%d", port)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
		client, err := nats.Connect(address, nats.Timeout(100*time.Millisecond), nats.NoReconnect())
		if err == nil {
			id := client.ConnectedServerId()
			client.Close()
			return fmt.Sprintf("nats://localhost:%d", port), id
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("standalone local NATS did not become ready: %s", logs.String())
	return "", ""
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
