package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func testResponseConfig(t *testing.T, serverURL, serverID string) responseConfig {
	t.Helper()
	nonce := randomConfig(t).Nonce
	digest := func(s string) string { value := sha256.Sum256([]byte(s)); return hex.EncodeToString(value[:]) }
	return responseConfig{BrokerURL: serverURL, Nonce: nonce,
		Subjects:              []string{"cat.response." + nonce + ".m0", "cat.response." + nonce + ".m1"},
		ExpectedPayloadSHA256: []string{digest("owned-m0"), digest("owned-m1")},
		AllowedServerIDs:      []string{serverID}, ConnectTimeoutMillis: 1000,
		FlushTimeoutMillis: 1000, M0TimeoutMillis: 800, M1TimeoutMillis: 800}
}

func writeResponseConfig(t *testing.T, cfg responseConfig) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "response.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func nextResponse(t *testing.T, scanner *bufio.Scanner) responseReceipt {
	t.Helper()
	if !scanner.Scan() {
		t.Fatalf("missing response receipt: %v", scanner.Err())
	}
	var row responseReceipt
	if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	return row
}

func publishResponse(t *testing.T, conn *nats.Conn, cfg responseConfig, phase int, data string, header string) {
	t.Helper()
	msg := nats.NewMsg(cfg.Subjects[phase])
	msg.Data = []byte(data)
	msg.Header.Set("Nats-Msg-Id", header)
	if err := conn.PublishMsg(msg); err != nil {
		t.Fatal(err)
	}
	if err := conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestResponseObserverRealBrokerTwoPhaseAndUnknownControls(t *testing.T) {
	binary := observerBinary(t)
	for _, mode := range []string{"exact", "m0-wrong", "m1-wrong", "m1-timeout", "wrong-server"} {
		t.Run(mode, func(t *testing.T) {
			srv := testServer(t, "")
			cfg := testResponseConfig(t, srv.ClientURL(), srv.ID())
			if mode == "wrong-server" {
				cfg.AllowedServerIDs = []string{"foreign-id"}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "--response-config", writeResponseConfig(t, cfg))
			cmd.Env = append(os.Environ(), "POD_UID=owned-pod-uid")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, 512), 2048)
			if mode == "wrong-server" {
				if scanner.Scan() {
					t.Fatalf("wrong broker emitted receipt: %q", scanner.Text())
				}
				if err := cmd.Wait(); err == nil || stderr.String() != "observer: BROKER_ID_MISMATCH\n" {
					t.Fatalf("wrong broker not refused: err=%v stderr=%q", err, stderr.String())
				}
				return
			}
			for i := 0; i < 2; i++ {
				row := nextResponse(t, scanner)
				if row.Kind != "subscription" || row.Phase != []string{"M0", "M1"}[i] || row.Subject != cfg.Subjects[i] || row.PodUID != "owned-pod-uid" || row.ServerID != srv.ID() || !row.Flushed || row.Status != "READY" {
					t.Fatalf("phase %d not preflushed with exact identity: %+v", i, row)
				}
			}
			writer, err := nats.Connect(srv.ClientURL(), nats.NoReconnect())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			m0 := "owned-m0"
			if mode == "m0-wrong" {
				m0 = "foreign-m0"
			}
			publishResponse(t, writer, cfg, 0, m0, "cat-"+cfg.Nonce)
			first := nextResponse(t, scanner)
			if first.Phase != "M0" || first.PodUID != "owned-pod-uid" || first.ServerID != srv.ID() {
				t.Fatalf("M0 identity lost: %+v", first)
			}
			if mode == "m0-wrong" {
				if first.Status != "IDENTITY_MISMATCH" || !first.NonceHeaderMatches || first.PayloadHashMatches {
					t.Fatalf("wrong M0 accepted: %+v", first)
				}
				if scanner.Scan() {
					t.Fatalf("M1 emitted after invalid M0: %q", scanner.Text())
				}
				if err := cmd.Wait(); err == nil || stderr.String() != "observer: M0_NOT_EXACT\n" {
					t.Fatalf("invalid M0 did not stop: %v %q", err, stderr.String())
				}
				return
			}
			if first.Status != "EXACT_PAYLOAD_RECEIVED" || first.PayloadSHA256 != cfg.ExpectedPayloadSHA256[0] {
				t.Fatalf("M0 disclosure not observed: %+v", first)
			}
			if mode != "m1-timeout" {
				header := "cat-" + cfg.Nonce
				if mode == "m1-wrong" {
					header = "cat-foreign"
				}
				publishResponse(t, writer, cfg, 1, "owned-m1", header)
			}
			second := nextResponse(t, scanner)
			if second.Kind != "observation" || second.Phase != "M1" || second.PodUID != first.PodUID || second.ServerID != first.ServerID || second.Subject != cfg.Subjects[1] {
				t.Fatalf("M1 did not stay on exact client: %+v", second)
			}
			want := "EXACT_PAYLOAD_RECEIVED"
			if mode == "m1-wrong" {
				want = "IDENTITY_MISMATCH"
			}
			if mode == "m1-timeout" {
				want = "TIMEOUT_UNKNOWN"
			}
			if second.Status != want {
				t.Fatalf("M1=%+v want %s", second, want)
			}
			if scanner.Scan() {
				t.Fatalf("extra response receipt: %q", scanner.Text())
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("response observer failed: %v %q", err, stderr.String())
			}
		})
	}
}

func TestResponseConfigRejectsAliasesDuplicatesReplayAndNoPodUID(t *testing.T) {
	cfg := testResponseConfig(t, "nats://localhost:4222", "SERVER_A")
	path := writeResponseConfig(t, cfg)
	if _, err := loadResponseConfig(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	variants := []string{
		strings.Replace(string(raw), `"nonce":`, `"Nonce":`, 1),
		strings.Replace(string(raw), `"nonce":`, `"nonce":"foreign","nonce":`, 1),
		strings.Replace(string(raw), `"subjects":[`, `"subjects":["cat.response.foreign.m0",`, 1),
		strings.Replace(string(raw), cfg.Subjects[1], cfg.Subjects[0], 1),
		strings.Replace(string(raw), cfg.ExpectedPayloadSHA256[1], cfg.ExpectedPayloadSHA256[0], 1),
		strings.Replace(string(raw), `"brokerURL":"nats://localhost:4222"`, `"brokerURL":"nats://user:secret@localhost:4222"`, 1),
	}
	for i, value := range variants {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadResponseConfig(path); err == nil {
			t.Fatalf("invalid response config %d accepted", i)
		}
	}
	if podUIDPattern.MatchString("") || podUIDPattern.MatchString("foreign uid") {
		t.Fatal("missing or malformed Pod UID accepted")
	}
}
