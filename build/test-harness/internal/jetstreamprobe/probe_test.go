package jetstreamprobe

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"
)

func TestRealPinnedJetStreamServerDurabilityProtocol(t *testing.T) {
	srv := startServer(t)
	cfg := testConfig(srv.ClientURL())
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)

	message := Message{ID: "nonce-a", Payload: []byte("nonce-bound-payload-a")}
	first, err := probe.Publish(t.Context(), message, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Stream != cfg.Stream || first.Sequence == 0 || first.Duplicate {
		t.Fatalf("first PubAck=%+v", first)
	}
	delivery, err := probe.ConsumeAndAck(t.Context(), message, first.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.StreamSequence != first.Sequence || delivery.Deliveries != 1 {
		t.Fatalf("delivery=%+v PubAck=%+v", delivery, first)
	}
	if err := probe.RequireNoSameConsumerRedelivery(t.Context()); err != nil {
		t.Fatalf("ACKed message redelivered to same consumer: %v", err)
	}
	stored, err := probe.GetStored(t.Context(), message, first.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if stored.StreamSequence != first.Sequence || stored.MessageID != message.ID {
		t.Fatalf("stored=%+v", stored)
	}
	fresh, err := probe.ConsumeStoredWithFreshConsumer(t.Context(), "probe-storage-check", message, first.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.StreamSequence != first.Sequence || fresh.MessageID != message.ID {
		t.Fatalf("fresh-consumer delivery=%+v", fresh)
	}
	duplicate, err := probe.Publish(t.Context(), message, true, first.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.Sequence != first.Sequence {
		t.Fatalf("bounded-window duplicate PubAck=%+v first=%+v", duplicate, first)
	}
	state, err := probe.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.Stream != cfg.Stream || state.Consumer != cfg.Consumer || state.Replicas != 1 || state.Messages != 1 || state.FirstSequence != first.Sequence || state.LastSequence != first.Sequence || state.AckFloor < first.Sequence || state.AckPending != 0 || state.ConsumerRedelivered != 0 {
		t.Fatalf("stream/consumer state=%+v", state)
	}
	monitorURL := fmt.Sprintf("http://127.0.0.1:%d", srv.MonitorAddr().Port)
	jsz, err := ReadJSZ(t.Context(), monitorURL, srv.ID(), cfg.Stream, cfg.Consumer, cfg.RequestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if jsz.ServerID != srv.ID() || jsz.Stream != cfg.Stream || jsz.Consumer != cfg.Consumer || jsz.StreamMessages != 1 {
		t.Fatalf("jsz receipt=%+v", jsz)
	}

	reqCtx, cancel := context.WithTimeout(t.Context(), cfg.RequestTimeout)
	defer cancel()
	info, err := probe.stream.Info(reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 || info.Config.Duplicates != cfg.DuplicateWindow {
		t.Fatalf("dedupe/storage state=%+v", info)
	}
}

func TestRealServerRefusesWrongStoredIdentity(t *testing.T) {
	srv := startServer(t)
	probe, err := Open(t.Context(), testConfig(srv.ClientURL()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	message := Message{ID: "nonce-a", Payload: []byte("payload-a")}
	ack, err := probe.Publish(t.Context(), message, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []Message{{ID: "nonce-b", Payload: message.Payload}, {ID: message.ID, Payload: []byte("payload-b")}} {
		if _, err := probe.GetStored(t.Context(), wrong, ack.Sequence); err == nil {
			t.Fatalf("wrong stored identity accepted: %+v", wrong)
		}
	}
	if _, err := probe.GetStored(t.Context(), message, ack.Sequence+1); err == nil {
		t.Fatal("wrong sequence accepted")
	}
}

func TestPubAckIdentityValidatorRefusesMalformedOrWrongReceipt(t *testing.T) {
	valid := &jetstream.PubAck{Stream: "DURABILITY", Sequence: 7}
	if err := validatePubAck(valid, "DURABILITY", false, 7); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		ack       *jetstream.PubAck
		stream    string
		duplicate bool
		sequence  uint64
	}{
		"nil":             {nil, "DURABILITY", false, 7},
		"wrong-stream":    {valid, "FOREIGN", false, 7},
		"zero-sequence":   {&jetstream.PubAck{Stream: "DURABILITY"}, "DURABILITY", false, 0},
		"wrong-sequence":  {valid, "DURABILITY", false, 8},
		"wrong-duplicate": {&jetstream.PubAck{Stream: "DURABILITY", Sequence: 7, Duplicate: true}, "DURABILITY", false, 7},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePubAck(tc.ack, tc.stream, tc.duplicate, tc.sequence); err == nil {
				t.Fatal("invalid PubAck accepted")
			}
		})
	}
}

func TestConnectionAndFetchAreBounded(t *testing.T) {
	cfg := testConfig("nats://127.0.0.1:1")
	cfg.ConnectTimeout = 40 * time.Millisecond
	started := time.Now()
	if _, err := Open(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "connect NATS") {
		t.Fatalf("unreachable server result=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("connection exceeded bound: %s", elapsed)
	}

	srv := startServer(t)
	cfg = testConfig(srv.ClientURL())
	cfg.FetchTimeout = 50 * time.Millisecond
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	started = time.Now()
	if _, err := probe.fetchOne(t.Context(), probe.consumer, cfg.FetchTimeout); err == nil {
		t.Fatal("empty stream fetch did not time out")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fetch exceeded bound: %s", elapsed)
	}
}

func TestConfigRequiresEveryPositiveBound(t *testing.T) {
	base := testConfig("nats://127.0.0.1:4222")
	if err := validateConfig(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"connect":   func(c *Config) { c.ConnectTimeout = 0 },
		"request":   func(c *Config) { c.RequestTimeout = 0 },
		"fetch":     func(c *Config) { c.FetchTimeout = 0 },
		"ack":       func(c *Config) { c.AckWait = 0 },
		"duplicate": func(c *Config) { c.DuplicateWindow = 0 },
		"replicas":  func(c *Config) { c.Replicas = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatal("zero bound accepted")
			}
		})
	}
}

func TestJSZRefusesWrongServerAndEndpointShape(t *testing.T) {
	srv := startServer(t)
	cfg := testConfig(srv.ClientURL())
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	base := fmt.Sprintf("http://127.0.0.1:%d", srv.MonitorAddr().Port)
	if _, err := ReadJSZ(t.Context(), base, "foreign-server", cfg.Stream, cfg.Consumer, cfg.RequestTimeout); err == nil {
		t.Fatal("wrong server identity accepted")
	}
	for _, invalid := range []string{base + "/foreign", base + "?streams=true", "file:///tmp/jsz", "http://user@127.0.0.1/"} {
		if _, err := exactJSZURL(invalid); err == nil {
			t.Fatalf("invalid monitor base accepted: %s", invalid)
		}
	}
}

func startServer(t *testing.T) *server.Server {
	t.Helper()
	if server.VERSION != "2.10.29" {
		t.Fatalf("test server version=%s, want pinned 2.10.29", server.VERSION)
	}
	srv, err := server.NewServer(&server.Options{JetStream: true, StoreDir: t.TempDir(), Port: -1, HTTPPort: -1, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("local JetStream server did not become ready")
	}
	t.Cleanup(func() {
		srv.Shutdown()
		srv.WaitForShutdown()
	})
	return srv
}

func testConfig(url string) Config {
	return Config{
		URL:             url,
		Stream:          "DURABILITY",
		Subject:         "fixture.durability",
		Consumer:        "durability-main",
		Replicas:        1,
		ConnectTimeout:  250 * time.Millisecond,
		RequestTimeout:  time.Second,
		FetchTimeout:    100 * time.Millisecond,
		AckWait:         500 * time.Millisecond,
		DuplicateWindow: 2 * time.Second,
	}
}
