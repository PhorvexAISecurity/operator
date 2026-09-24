package natsexposure

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func startServer(t *testing.T, users []*server.User) *server.Server {
	t.Helper()
	if server.VERSION != "2.10.29" {
		t.Fatalf("server version=%s, want 2.10.29", server.VERSION)
	}
	srv, err := server.NewServer(&server.Options{JetStream: true, StoreDir: t.TempDir(), Port: -1, NoSigs: true, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("pinned NATS server not ready")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	return srv
}

func connect(t *testing.T, url, user, password string) *nats.Conn {
	t.Helper()
	options := []nats.Option{nats.MaxReconnects(0), nats.PermissionErrOnSubscribe(true), nats.Timeout(time.Second)}
	if user != "" {
		options = append(options, nats.UserInfo(user, password))
	}
	nc, err := nats.Connect(url, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func config(serverID string) Config {
	return Config{Nonce: "abc12345", Stream: "CAT_abc12345", Subject: "cat.abc12345",
		Consumer: "CAT_CON_abc12345", ExpectedWriterServerID: serverID,
		ExpectedAdversaryServerID: serverID, RequestTimeout: time.Second,
		ReceiveTimeout: 200 * time.Millisecond, AckWait: time.Second, BarrierTimeout: time.Second}
}

func recordPhase(_ context.Context, _ Receipt) error  { return nil }
func allowPublish(_ context.Context, _ Receipt) error { return nil }

func requireGone(t *testing.T, writer *nats.Conn, name string) {
	t.Helper()
	js, err := jetstream.New(writer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = js.Stream(t.Context(), name)
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("owned stream still present or unknown: %v", err)
	}
}

func TestRealServerExactPayloadExposureAndLegitimateControl(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	adversary := connect(t, srv.ClientURL(), "", "")
	cfg := config(srv.ID())
	var phases []string
	recorder := func(_ context.Context, receipt Receipt) error {
		phases = append(phases, receipt.Phase)
		return nil
	}
	barrierCalls := 0
	barrier := func(_ context.Context, receipt Receipt) error {
		barrierCalls++
		if !receipt.SubscriptionFlushed || receipt.PublishAttempted {
			t.Fatalf("barrier called outside prepublication window: %+v", receipt)
		}
		return nil
	}
	got, err := Run(t.Context(), cfg, writer, adversary, bytes.Repeat([]byte{'x'}, maxPayload), recorder, barrier)
	if err != nil {
		t.Fatal(err)
	}
	if got.Validity != "VALID" || got.Objective != "REACHED" || got.AdversaryObservation != "EXACT_PAYLOAD_RECEIVED" || !got.SubscriptionFlushed || !got.LegitimateAcked || got.PubAckSequence != 1 || got.Cleanup != "CONFIRMED_ABSENT" || got.AdversaryPayloadSHA256 != got.PayloadSHA256 || got.LegitimatePayloadSHA256 != got.PayloadSHA256 || got.StoredPayloadSHA256 != got.PayloadSHA256 || got.AdversaryServerID != srv.ID() {
		t.Fatalf("protocol receipt=%+v", got)
	}
	if barrierCalls != 1 || !before(phases, "CREATE_INTENT", "CREATE_RESPONSE") || !before(phases, "SUBSCRIPTION_FLUSHED", "PUBLISH_INTENT") || !before(phases, "PUBLISH_INTENT", "PUBACK_VERIFIED") || !before(phases, "DELETE_INTENT", "DONE") {
		t.Fatalf("phase sequence=%v barrierCalls=%d", phases, barrierCalls)
	}
	requireGone(t, writer, cfg.Stream)
	oversized, err := Run(t.Context(), cfg, writer, adversary, bytes.Repeat([]byte{'x'}, maxPayload+1), recordPhase, allowPublish)
	if err == nil || oversized.PublishAttempted || oversized.Cleanup != "NOT_CREATED" {
		t.Fatalf("257-byte payload was not refused before mutation: receipt=%+v err=%v", oversized, err)
	}
	requireGone(t, writer, cfg.Stream)
}

func TestRealServerSubjectDenialIsNotExposure(t *testing.T) {
	cfg := config("placeholder")
	srv := startServer(t, []*server.User{
		{Username: "writer", Password: "synthetic-writer"},
		{Username: "reader", Password: "synthetic-reader", Permissions: &server.Permissions{
			Subscribe: &server.SubjectPermission{Allow: []string{">"}, Deny: []string{cfg.Subject}},
		}},
	})
	writer := connect(t, srv.ClientURL(), "writer", "synthetic-writer")
	adversary := connect(t, srv.ClientURL(), "reader", "synthetic-reader")
	cfg.ExpectedWriterServerID, cfg.ExpectedAdversaryServerID = srv.ID(), srv.ID()
	got, err := Run(t.Context(), cfg, writer, adversary, []byte("owned synthetic message"), recordPhase, allowPublish)
	if err != nil {
		t.Fatal(err)
	}
	if got.Validity != "VALID" || got.Objective != "NOT_REACHED" || got.AdversaryObservation != "SUBSCRIPTION_DENIED" || !got.LegitimateAcked || got.Cleanup != "CONFIRMED_ABSENT" {
		t.Fatalf("subject-denial receipt=%+v", got)
	}
	requireGone(t, writer, cfg.Stream)
}

func TestWrongBrokerAndNonceRefuseBeforeCreate(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	adversary := connect(t, srv.ClientURL(), "", "")
	for _, change := range []func(*Config){
		func(c *Config) { c.ExpectedAdversaryServerID = "wrong-server" },
		func(c *Config) { c.Nonce = "wrongnonce" },
	} {
		cfg := config(srv.ID())
		change(&cfg)
		got, err := Run(t.Context(), cfg, writer, adversary, []byte("owned"), recordPhase, allowPublish)
		if err == nil || got.PublishAttempted || got.Cleanup != "NOT_CREATED" {
			t.Fatalf("wrong identity accepted: receipt=%+v err=%v", got, err)
		}
		requireGone(t, writer, cfg.Stream)
	}
}

func TestNoPayloadTimeoutIsUnknownNotDenial(t *testing.T) {
	srv := startServer(t, nil)
	adversary := connect(t, srv.ClientURL(), "", "")
	cfg := config(srv.ID())
	cfg.ReceiveTimeout = 30 * time.Millisecond
	sub, err := adversary.SubscribeSync(cfg.Subject)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := adversary.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	got := Receipt{Objective: "UNKNOWN"}
	if err := observeAdversary(context.Background(), cfg, sub, []byte("owned"), &got); err == nil || got.AdversaryObservation != "TIMEOUT_OR_TRANSPORT_UNKNOWN" || got.Objective != "UNKNOWN" {
		t.Fatalf("timeout misclassified: receipt=%+v err=%v", got, err)
	}
}

func TestAdversarySamePayloadWithoutNonceHeaderIsWrongMessage(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	adversary := connect(t, srv.ClientURL(), "", "")
	cfg := config(srv.ID())
	sub, err := adversary.SubscribeSync(cfg.Subject)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := adversary.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := writer.Publish(cfg.Subject, []byte("owned")); err != nil {
		t.Fatal(err)
	}
	got := Receipt{Objective: "UNKNOWN"}
	if err := observeAdversary(t.Context(), cfg, sub, []byte("owned"), &got); err == nil || got.AdversaryObservation != "WRONG_MESSAGE" || got.Objective != "UNKNOWN" {
		t.Fatalf("unbound header accepted: receipt=%+v err=%v", got, err)
	}
}

func TestCleanupWithholdsMismatchedStreamOwner(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	js, err := jetstream.New(writer)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(srv.ID())
	stream, err := js.CreateStream(t.Context(), jetstream.StreamConfig{
		Name: cfg.Stream, Subjects: []string{cfg.Subject}, Storage: jetstream.FileStorage,
		Replicas: 1, MaxMsgs: 3, MaxBytes: maxStreamBytes, MaxAge: 120 * time.Second, MaxConsumers: 1, MaxMsgSize: maxWireBytes,
		Metadata: metadata("different-nonce"),
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result := cleanup(t.Context(), cfg, js, info.Created, func() error { return nil }); result != "WITHHELD_OWNERSHIP_MISMATCH" {
		t.Fatalf("cleanup=%s", result)
	}
	if _, err := js.Stream(t.Context(), cfg.Stream); err != nil {
		t.Fatalf("foreign stream deleted: %v", err)
	}
}

func TestCleanupWithholdsDifferentCreateResponseTimestamp(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	js, err := jetstream.New(writer)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(srv.ID())
	stream, err := js.CreateStream(t.Context(), jetstream.StreamConfig{
		Name: cfg.Stream, Subjects: []string{cfg.Subject}, Storage: jetstream.FileStorage,
		Replicas: 1, MaxMsgs: 3, MaxBytes: maxStreamBytes, MaxAge: 120 * time.Second,
		MaxConsumers: 1, MaxMsgSize: maxWireBytes, Metadata: metadata(cfg.Nonce),
	})
	if err != nil {
		t.Fatal(err)
	}
	created := stream.CachedInfo().Created
	if result := cleanup(t.Context(), cfg, js, created.Add(-time.Second), func() error { return nil }); result != "WITHHELD_OWNERSHIP_MISMATCH" {
		t.Fatalf("cleanup=%s", result)
	}
	if _, err := js.Stream(t.Context(), cfg.Stream); err != nil {
		t.Fatalf("changed-created identity deleted: %v", err)
	}
}

func TestRecorderFailureBeforeCreateAbortsWithoutStream(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	adversary := connect(t, srv.ClientURL(), "", "")
	cfg := config(srv.ID())
	barrierCalls := 0
	recorder := func(_ context.Context, receipt Receipt) error {
		if receipt.Phase == "CREATE_INTENT" {
			return errors.New("synthetic disk failure")
		}
		return nil
	}
	got, err := Run(t.Context(), cfg, writer, adversary, []byte("owned"), recorder,
		func(context.Context, Receipt) error { barrierCalls++; return nil })
	if err == nil || got.PublishAttempted || got.Cleanup != "NOT_CREATED" || barrierCalls != 0 {
		t.Fatalf("mutation after recorder failure: receipt=%+v err=%v", got, err)
	}
	requireGone(t, writer, cfg.Stream)
}

func TestBarrierRefusalAndPublishIntentFailureNeverPublish(t *testing.T) {
	for _, stop := range []string{"barrier", "PUBLISH_INTENT"} {
		t.Run(stop, func(t *testing.T) {
			srv := startServer(t, nil)
			writer := connect(t, srv.ClientURL(), "", "")
			adversary := connect(t, srv.ClientURL(), "", "")
			cfg := config(srv.ID())
			recorder := func(_ context.Context, receipt Receipt) error {
				if receipt.Phase == stop {
					return errors.New("synthetic disk failure")
				}
				return nil
			}
			barrier := func(context.Context, Receipt) error {
				if stop == "barrier" {
					return errors.New("independent decision absent")
				}
				return nil
			}
			got, err := Run(t.Context(), cfg, writer, adversary, []byte("owned"), recorder, barrier)
			if err == nil || got.PublishAttempted || got.Cleanup != "CONFIRMED_ABSENT" || got.Validity != "INCONCLUSIVE" {
				t.Fatalf("published despite gate failure: receipt=%+v err=%v", got, err)
			}
			requireGone(t, writer, cfg.Stream)
		})
	}
}

func TestCanceledBarrierStillRecordsAndCleansWithFreshContext(t *testing.T) {
	srv := startServer(t, nil)
	writer := connect(t, srv.ClientURL(), "", "")
	adversary := connect(t, srv.ClientURL(), "", "")
	cfg := config(srv.ID())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var cleanupPhases []string
	recorder := func(recordCtx context.Context, receipt Receipt) error {
		if recordCtx.Err() != nil {
			return errors.New("recorder refuses canceled context")
		}
		if receipt.Phase == "DELETE_INTENT" || receipt.Phase == "DONE" {
			cleanupPhases = append(cleanupPhases, receipt.Phase)
		}
		return nil
	}
	got, err := Run(ctx, cfg, writer, adversary, []byte("owned"), recorder,
		func(context.Context, Receipt) error { cancel(); return nil })
	if err == nil || got.PublishAttempted || got.Cleanup != "CONFIRMED_ABSENT" || len(cleanupPhases) != 2 || cleanupPhases[0] != "DELETE_INTENT" || cleanupPhases[1] != "DONE" {
		t.Fatalf("canceled barrier cleanup: receipt=%+v phases=%v err=%v", got, cleanupPhases, err)
	}
	requireGone(t, writer, cfg.Stream)
}

func TestPublishNoResponderDispatchesExactlyOnce(t *testing.T) {
	if server.VERSION != "2.10.29" {
		t.Fatalf("server version=%s", server.VERSION)
	}
	srv, err := server.NewServer(&server.Options{Port: -1, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("plain server not ready")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	writer := connect(t, srv.ClientURL(), "", "")
	js, err := jetstream.New(writer)
	if err != nil {
		t.Fatal(err)
	}
	before := writer.Stats().OutMsgs
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = publishOnce(ctx, js, nats.NewMsg("cat.abc12345"))
	if !errors.Is(err, jetstream.ErrNoStreamResponse) {
		t.Fatalf("missing no-responder boundary: %v", err)
	}
	if sent := writer.Stats().OutMsgs - before; sent != 1 {
		t.Fatalf("publish dispatch count=%d, want exactly one", sent)
	}
}

func before(phases []string, first, last string) bool {
	for i, phase := range phases {
		if phase == first {
			for _, later := range phases[i+1:] {
				if later == last {
					return true
				}
			}
		}
	}
	return false
}
