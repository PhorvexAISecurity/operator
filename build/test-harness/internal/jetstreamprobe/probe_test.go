package jetstreamprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
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

func TestOpenRefusesPreexistingStreamAndConsumerWithoutMutation(t *testing.T) {
	for _, matchingOwnership := range []bool{false, true} {
		t.Run(fmt.Sprintf("matching-ownership-%t", matchingOwnership), func(t *testing.T) {
			srv := startServer(t)
			cfg := testConfig(srv.ClientURL())
			nc, err := nats.Connect(cfg.URL, nats.Timeout(cfg.ConnectTimeout), nats.MaxReconnects(0))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(nc.Close)
			js, err := jetstream.New(nc)
			if err != nil {
				t.Fatal(err)
			}
			metadata := ownershipMetadata("foreign-owner")
			if matchingOwnership {
				metadata = ownershipMetadata(cfg.OwnerNonce)
			}
			stream, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: cfg.Stream, Subjects: []string{cfg.Subject}, Storage: jetstream.FileStorage, Replicas: cfg.Replicas, Duplicates: cfg.DuplicateWindow, Metadata: metadata})
			if err != nil {
				t.Fatal(err)
			}
			consumer, err := stream.CreateConsumer(t.Context(), jetstream.ConsumerConfig{Durable: cfg.Consumer, AckPolicy: jetstream.AckExplicitPolicy, AckWait: cfg.AckWait, MaxDeliver: 2, FilterSubject: cfg.Subject, Metadata: metadata})
			if err != nil {
				t.Fatal(err)
			}
			msg := nats.NewMsg(cfg.Subject)
			msg.Header.Set(messageIDHeader, "foreign-message")
			msg.Data = []byte("foreign-payload")
			if _, err := js.PublishMsg(t.Context(), msg); err != nil {
				t.Fatal(err)
			}
			beforeConsumer := waitForConsumerPending(t, consumer, 1, cfg.RequestTimeout)
			beforeStream, err := stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(t.Context(), cfg); err == nil || opened != nil || !strings.Contains(err.Error(), "refusing preexisting stream") {
				t.Fatalf("preexisting fixture result probe=%v err=%v", opened, err)
			}
			afterStream, err := stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			afterConsumer, err := consumer.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(beforeStream.Config, afterStream.Config) || !reflect.DeepEqual(beforeStream.State, afterStream.State) || !reflect.DeepEqual(beforeConsumer.Config, afterConsumer.Config) || beforeConsumer.Delivered != afterConsumer.Delivered || beforeConsumer.AckFloor != afterConsumer.AckFloor || beforeConsumer.NumPending != afterConsumer.NumPending || beforeConsumer.NumAckPending != afterConsumer.NumAckPending {
				t.Fatalf("preexisting stream or consumer mutated\nbefore stream=%+v\nafter stream=%+v\nbefore consumer=%+v\nafter consumer=%+v", beforeStream, afterStream, beforeConsumer, afterConsumer)
			}
		})
	}
}

func TestDistinctStorageCheckRefusesPreexistingConsumerWithoutMutation(t *testing.T) {
	for _, matchingOwnership := range []bool{false, true} {
		t.Run(fmt.Sprintf("matching-ownership-%t", matchingOwnership), func(t *testing.T) {
			srv := startServer(t)
			cfg := testConfig(srv.ClientURL())
			probe, err := Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(probe.Close)
			message := Message{ID: "nonce-a", Payload: []byte("payload-a")}
			ack, err := probe.Publish(t.Context(), message, false, 0)
			if err != nil {
				t.Fatal(err)
			}
			metadata := ownershipMetadata("foreign-owner")
			if matchingOwnership {
				metadata = ownershipMetadata(cfg.OwnerNonce)
			}
			const name = "preexisting-storage-check"
			consumer, err := probe.stream.CreateConsumer(t.Context(), jetstream.ConsumerConfig{Name: name, AckPolicy: jetstream.AckExplicitPolicy, DeliverPolicy: jetstream.DeliverByStartSequencePolicy, OptStartSeq: ack.Sequence, FilterSubject: cfg.Subject, AckWait: cfg.AckWait, MaxDeliver: 1, Metadata: metadata})
			if err != nil {
				t.Fatal(err)
			}
			before := waitForConsumerPending(t, consumer, 1, cfg.RequestTimeout)
			if _, err := probe.ConsumeStoredWithFreshConsumer(t.Context(), name, message, ack.Sequence); err == nil || !strings.Contains(err.Error(), "refusing preexisting distinct consumer") {
				t.Fatalf("preexisting distinct consumer accepted: %v", err)
			}
			after, err := consumer.Info(t.Context())
			if err != nil {
				t.Fatalf("preexisting consumer was deleted: %v", err)
			}
			if !reflect.DeepEqual(before.Config, after.Config) || before.Delivered != after.Delivered || before.AckFloor != after.AckFloor || before.NumPending != after.NumPending || before.NumAckPending != after.NumAckPending {
				t.Fatalf("preexisting distinct consumer mutated\nbefore=%+v\nafter=%+v", before, after)
			}
			stored, err := probe.GetStored(t.Context(), message, ack.Sequence)
			if err != nil || stored.StreamSequence != ack.Sequence {
				t.Fatalf("stored message changed: %+v err=%v", stored, err)
			}
		})
	}
}

type testMessageBatch struct {
	messages chan jetstream.Msg
	err      error
}

func (b testMessageBatch) Messages() <-chan jetstream.Msg { return b.messages }
func (b testMessageBatch) Error() error                   { return b.err }

func TestCompletedNoRedeliveryWindowDrainsQueuedMessageBeforePassing(t *testing.T) {
	srv := startServer(t)
	cfg := testConfig(srv.ClientURL())
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	message := Message{ID: "queued-after-window", Payload: []byte("must-not-pass")}
	ack, err := probe.Publish(t.Context(), message, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := probe.consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	msg := <-batch.Messages()
	if msg == nil {
		t.Fatal("real server did not deliver queued message")
	}
	meta, err := msg.Metadata()
	if err != nil || meta.Sequence.Stream != ack.Sequence {
		t.Fatalf("queued message metadata=%+v err=%v", meta, err)
	}
	queued := make(chan jetstream.Msg, 1)
	queued <- msg
	close(queued)
	if err := probe.finishNoRedeliveryWindow(t.Context(), testMessageBatch{messages: queued, err: context.Canceled}); err == nil || !strings.Contains(err.Error(), "redelivered") {
		t.Fatalf("queued delivery after completed window was accepted: %v", err)
	}
}

func TestCanceledNoRedeliveryWindowNeverPasses(t *testing.T) {
	srv := startServer(t)
	cfg := testConfig(srv.ClientURL())
	cfg.FetchTimeout = 2 * time.Second
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := probe.RequireNoSameConsumerRedelivery(ctx); err == nil {
		t.Fatal("canceled observation was accepted as no redelivery")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled observation exceeded caller bound: %s", elapsed)
	}
}

func TestConnectHonorsCallerCancellationDuringHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	cfg := testConfig("nats://" + listener.Addr().String())
	cfg.ConnectTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if probe, err := Open(ctx, cfg); err == nil || probe != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled handshake probe=%v err=%v", probe, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled handshake exceeded caller bound: %s", elapsed)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	default:
	}
}

func TestDistinctConsumerCleanupFailureIsSurfaced(t *testing.T) {
	srv := startServer(t)
	cfg := testConfig(srv.ClientURL())
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	message := Message{ID: "nonce-a", Payload: []byte("payload-a")}
	ack, err := probe.Publish(t.Context(), message, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	deleteConsumer := probe.deleteConsumer
	probe.deleteConsumer = func(ctx context.Context, name string) error {
		srv.Shutdown()
		srv.WaitForShutdown()
		return deleteConsumer(ctx, name)
	}
	if _, err := probe.ConsumeStoredWithFreshConsumer(t.Context(), "cleanup-must-surface", message, ack.Sequence); err == nil || !strings.Contains(err.Error(), "cleanup distinct consumer") {
		t.Fatalf("cleanup failure was hidden: %v", err)
	}
}

func TestOwnedConsumerDeleteOutlastsTheStoreRemovalRace(t *testing.T) {
	race := &jetstream.APIError{Code: 500, ErrorCode: jsStreamGeneralError, Description: "unlinkat /tmp/js/obs/probe-storage-check: directory not empty"}
	other := &jetstream.APIError{Code: 500, ErrorCode: 10052, Description: "stream store failure"}
	for name, tc := range map[string]struct {
		answers []error
		calls   int
		want    error
	}{
		"deleted":                  {answers: []error{nil}, calls: 1},
		"gone after the race":      {answers: []error{race, jetstream.ErrConsumerNotFound}, calls: 2},
		"deleted after the race":   {answers: []error{race, race, nil}, calls: 3},
		"absent before any delete": {answers: []error{jetstream.ErrConsumerNotFound}, calls: 1, want: jetstream.ErrConsumerNotFound},
		"another failure":          {answers: []error{other}, calls: 1, want: other},
		"the race persists":        {answers: []error{race, race, race, race, race, race}, calls: consumerDeleteAttempts, want: race},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			probe := &Probe{deleteConsumer: func(context.Context, string) error {
				calls++
				return tc.answers[calls-1]
			}}
			err := probe.deleteOwnedConsumer(t.Context(), "probe-storage-check")
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
			if calls != tc.calls {
				t.Fatalf("deleted %d times, want %d", calls, tc.calls)
			}
		})
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
		"owner":     func(c *Config) { c.OwnerNonce = "" },
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

func waitForConsumerPending(t *testing.T, consumer jetstream.Consumer, want uint64, timeout time.Duration) *jetstream.ConsumerInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	for {
		info, err := consumer.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.NumPending == want {
			return info
		}
		select {
		case <-ctx.Done():
			t.Fatalf("consumer pending=%d, want %d before timeout", info.NumPending, want)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func testConfig(url string) Config {
	return Config{
		URL:             url,
		Stream:          "DURABILITY",
		Subject:         "fixture.durability",
		Consumer:        "durability-main",
		OwnerNonce:      "test-fixture-owner-7f2710f8",
		Replicas:        1,
		ConnectTimeout:  250 * time.Millisecond,
		RequestTimeout:  time.Second,
		FetchTimeout:    100 * time.Millisecond,
		AckWait:         500 * time.Millisecond,
		DuplicateWindow: 2 * time.Second,
	}
}
