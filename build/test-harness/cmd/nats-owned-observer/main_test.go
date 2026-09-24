package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func testServer(t *testing.T, deniedSubject string) *server.Server {
	t.Helper()
	if server.VERSION != "2.10.29" {
		t.Fatalf("NATS server version=%s, want 2.10.29", server.VERSION)
	}
	opts := &server.Options{Port: -1, NoSigs: true}
	if deniedSubject != "" {
		opts.NoAuthUser = "anonymous"
		opts.Users = []*server.User{{Username: "anonymous", Password: "synthetic-only", Permissions: &server.Permissions{
			Subscribe: &server.SubjectPermission{Allow: []string{">"}, Deny: []string{deniedSubject}},
		}}}
	}
	srv, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("local NATS server not ready")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	return srv
}

func observerBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nats-owned-observer")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBinary, "build", "-o", path, ".")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1", "GOFLAGS=-p=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build observer subprocess binary: %v: %s", err, output)
	}
	return path
}

func randomConfig(t *testing.T) config {
	t.Helper()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	value := hex.EncodeToString(nonce[:])
	return config{Nonce: value, Subject: "cat." + value,
		ConnectTimeoutMillis: 1000, FlushTimeoutMillis: 1000, ObserveTimeoutMillis: 400,
	}
}

func writeConfig(t *testing.T, cfg config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observer.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readReceipt(t *testing.T, scanner *bufio.Scanner) receipt {
	t.Helper()
	if !scanner.Scan() {
		t.Fatalf("missing observer receipt: %v", scanner.Err())
	}
	var result receipt
	if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
		t.Fatalf("invalid observer JSON receipt: %v", err)
	}
	return result
}

func TestObserverRealServerSubprocess(t *testing.T) {
	binary := observerBinary(t)
	if output, err := exec.Command(binary, "--publish").CombinedOutput(); err == nil || len(output) > 128 {
		t.Fatalf("unsupported command mode not boundedly rejected: err=%v outputBytes=%d", err, len(output))
	}
	for _, mode := range []string{"matching", "wrong-header", "oversize", "timeout", "denied", "wrong-server"} {
		t.Run(mode, func(t *testing.T) {
			cfg := randomConfig(t)
			payload := []byte("owned synthetic payload")
			if mode == "oversize" {
				payload = bytes.Repeat([]byte{'x'}, 257)
			}
			sum := sha256.Sum256(payload)
			cfg.ExpectedPayloadSHA256 = hex.EncodeToString(sum[:])
			denied := ""
			if mode == "denied" {
				denied = cfg.Subject
			}
			srv := testServer(t, denied)
			cfg.BrokerURL = srv.ClientURL()
			cfg.AllowedServerIDs = []string{srv.ID()}
			if mode == "wrong-server" {
				cfg.AllowedServerIDs = []string{"unadmitted-server"}
			}
			path := writeConfig(t, cfg)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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
			if mode == "wrong-server" {
				all, readErr := io.ReadAll(io.LimitReader(stdout, 2049))
				if readErr != nil || len(all) != 0 {
					t.Fatalf("wrong broker produced subscription receipt: bytes=%d readErr=%v", len(all), readErr)
				}
				if err := command.Wait(); err == nil || stderr.Len() > 128 {
					t.Fatalf("wrong broker not boundedly refused: err=%v stderrBytes=%d", err, stderr.Len())
				}
				return
			}
			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, 512), 2048)
			handshake := readReceipt(t, scanner)
			if handshake.Kind != "subscription" || !handshake.Flushed || handshake.Subject != cfg.Subject || handshake.Nonce != cfg.Nonce || handshake.ServerID != srv.ID() {
				t.Fatalf("subscription not pinned before publication: %+v", handshake)
			}
			if mode == "matching" || mode == "wrong-header" || mode == "oversize" {
				if handshake.Status != "READY" {
					t.Fatalf("unexpected handshake: %+v", handshake)
				}
				writer, err := nats.Connect(srv.ClientURL(), nats.MaxReconnects(0))
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				message := nats.NewMsg(cfg.Subject)
				message.Data = payload
				if mode != "wrong-header" {
					message.Header.Set("Nats-Msg-Id", "cat-"+cfg.Nonce)
				} else {
					message.Header.Set("Nats-Msg-Id", "cat-wrong")
				}
				if err := writer.PublishMsg(message); err != nil {
					t.Fatal(err)
				}
				if err := writer.FlushTimeout(time.Second); err != nil {
					t.Fatal(err)
				}
			}
			observation := readReceipt(t, scanner)
			if observation.Kind != "observation" || observation.ServerID != srv.ID() {
				t.Fatalf("observation broker identity differs: %+v", observation)
			}
			switch mode {
			case "matching":
				if observation.Status != "EXACT_PAYLOAD_RECEIVED" || !observation.NonceHeaderMatches || !observation.PayloadHashMatches || observation.PayloadSHA256 != cfg.ExpectedPayloadSHA256 || observation.PayloadBytes != len(payload) {
					t.Fatalf("bound message not observed: %+v", observation)
				}
			case "wrong-header":
				if observation.Status != "IDENTITY_MISMATCH" || observation.NonceHeaderMatches || !observation.PayloadHashMatches {
					t.Fatalf("wrong header accepted: %+v", observation)
				}
			case "oversize":
				if observation.Status != "OVERSIZE_INVALID" || observation.PayloadSHA256 != "" {
					t.Fatalf("257-byte payload accepted: %+v", observation)
				}
			case "timeout":
				if observation.Status != "TIMEOUT_UNKNOWN" {
					t.Fatalf("timeout misclassified: %+v", observation)
				}
			case "denied":
				if observation.Status != "PERMISSION_DENIED" {
					t.Fatalf("explicit denial not classified: handshake=%+v observation=%+v", handshake, observation)
				}
			}
			if scanner.Scan() {
				t.Fatalf("observer emitted extra JSON line: %q", scanner.Text())
			}
			if err := command.Wait(); err != nil {
				t.Fatalf("observer subprocess failed: %v: %s", err, stderr.String())
			}
		})
	}
}

func TestObserverRejectsUnboundedOrCredentialedConfig(t *testing.T) {
	cfg := randomConfig(t)
	cfg.BrokerURL = "nats://user:secret@127.0.0.1:4222"
	cfg.AllowedServerIDs = []string{"SERVER_A"}
	cfg.ExpectedPayloadSHA256 = strings.Repeat("0", 64)
	if err := validate(cfg); err == nil {
		t.Fatal("credentialed URL accepted")
	}
	cfg.BrokerURL = "nats://127.0.0.1:4222"
	cfg.Subject += ".*"
	if err := validate(cfg); err == nil {
		t.Fatal("wildcard subject accepted")
	}
}
