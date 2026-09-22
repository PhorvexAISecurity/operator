package scopedoutcome

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

type m106MemoryEvidence struct {
	mu            sync.Mutex
	bundles       []EvidenceBundle
	block         <-chan struct{}
	entered       chan<- struct{}
	err           error
	ignoreContext bool
	calls         atomic.Int32
}

type m106StaticResolver struct{}

func (m106StaticResolver) Resolve(_ context.Context, config PrepareConfig) (model.PersistenceWorkloadScope, int64, error) {
	return config.Workload, config.TargetTerminationGraceSeconds, nil
}
func (m106StaticResolver) SnapshotReplacementBoundary(_ context.Context, config PrepareConfig) ([]string, error) {
	return []string{config.TargetUID}, nil
}
func (m106StaticResolver) ResolveReplacement(_ context.Context, config PrepareConfig, _ []string, claimedUID string, _ time.Time) error {
	if claimedUID == "" || claimedUID == config.TargetUID {
		return errors.New("invalid replacement UID")
	}
	return nil
}

type m106TimedResolver struct {
	m106StaticResolver
	createdAt time.Time
}

func (r m106TimedResolver) ResolveReplacement(ctx context.Context, config PrepareConfig, preexisting []string, claimedUID string, dispatchedAt time.Time) error {
	if !r.createdAt.After(dispatchedAt) {
		return errors.New("replacement creation did not follow acknowledged dispatch")
	}
	return r.m106StaticResolver.ResolveReplacement(ctx, config, preexisting, claimedUID, dispatchedAt)
}

type m106Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *m106Clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *m106Clock) Set(value time.Time) { c.mu.Lock(); c.now = value; c.mu.Unlock() }

func m106PreparedProducer(t *testing.T, store EvidenceStore) (*Producer, PrepareConfig, *m106Clock) {
	t.Helper()
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	digest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		session := r.URL.Query().Get("session")
		target := "uid"
		if session == "new" {
			target = "new-uid"
		}
		body, _ := json.Marshal(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: session, Challenge: r.URL.Query().Get("challenge"), Present: true, TargetUID: target, WorkloadScopeSHA256: digest})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	clock := &m106Clock{now: time.Date(2026, 9, 21, 5, 0, 0, 0, time.UTC)}
	producer, err := newProducer(client, store, m106StaticResolver{}, "epoch", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	producer.waitUntil = func(ctx context.Context, deadline time.Time) bool { clock.Set(deadline); return ctx.Err() == nil }
	config := PrepareConfig{Policy: model.PolicyEpoch{Namespace: "ns", Name: "p", UID: "u", Generation: 1}, Workload: workload,
		TargetUID: "uid", TargetName: "pod", TargetTerminationGraceSeconds: 30,
		Old:         SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "before", TargetUID: "uid", WorkloadScopeSHA256: digest},
		Replacement: SessionEndpoint{URL: "https://session.test/new", SessionID: "new", Challenge: "after", WorkloadScopeSHA256: digest}}
	if err := producer.Prepare(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	return producer, config, clock
}

func (s *m106MemoryEvidence) Put(ctx context.Context, bundle EvidenceBundle) error {
	s.calls.Add(1)
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.block != nil {
		if s.ignoreContext {
			<-s.block
		} else {
			select {
			case <-s.block:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles = append(s.bundles, bundle)
	return nil
}

func TestPost25M106HungEvidenceStoreHasOneInFlightWrite(t *testing.T) {
	block := make(chan struct{})
	store := &m106MemoryEvidence{block: block, ignoreContext: true}
	producer, err := newProducer(&http.Client{Transport: m106RoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}, store, m106StaticResolver{}, "epoch", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	firstCtx, firstCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer firstCancel()
	if err := producer.putEvidence(firstCtx, EvidenceBundle{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first write err=%v", err)
	}
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := producer.putEvidence(ctx, EvidenceBundle{})
		cancel()
		if err == nil || !strings.Contains(err.Error(), "in-flight") {
			t.Fatalf("write %d was not refused: %v", i+2, err)
		}
	}
	if got := store.calls.Load(); got != 1 {
		t.Fatalf("hung store calls=%d want 1", got)
	}
	close(block)
}

func TestPost25M106CloseIsBoundedWhenEvidenceStoreIgnoresCancellation(t *testing.T) {
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	store := &m106MemoryEvidence{block: block, entered: entered, ignoreContext: true}
	producer, _, clock := m106PreparedProducer(t, store)
	policy := model.Policy{Namespace: "ns", PolicyName: "p", PolicyUID: "u", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "pod", UID: "uid"}}
	request := actuator.Request{PolicyName: "p", PolicyUID: "u", Namespace: "ns", Pod: "pod", TargetUID: "uid", Action: model.ActionRotate}
	if !producer.RecordNativeRotate(policy, view, request, actuator.Result{Actuator: "native", Handler: "rotate", Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/pod"}}, clock.Now()) {
		t.Fatal("prepared coherent operation was not queued")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter evidence store")
	}
	done := make(chan struct{})
	go func() { producer.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("producer Close waited for a non-cooperative evidence store")
	}
	close(block)
	for _, delivery := range producer.Drain(4) {
		if delivery.Observation != nil {
			t.Fatalf("shutdown admitted evidence retained after cancellation: %+v", delivery)
		}
	}
}

func TestPost25M106MTLSOldSessionToRevokedOutcome(t *testing.T) {
	ca, caKey, roots := m106CA(t)
	serverCert := m106Leaf(t, ca, caKey, "session.test", x509.ExtKeyUsageServerAuth)
	clientCert := m106Leaf(t, ca, caKey, "observer.test", x509.ExtKeyUsageClientAuth)
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "deployment-uid"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	rotated := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		changed := rotated
		mu.Unlock()
		session, challenge := r.URL.Query().Get("session"), r.URL.Query().Get("challenge")
		present := session == "old-session" && !changed || session == "new-session" && changed
		status := http.StatusOK
		if !present {
			status = http.StatusGone
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		targetUID := "old-pod-uid"
		if session == "new-session" {
			targetUID = "new-pod-uid"
		}
		_ = json.NewEncoder(w).Encode(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: session, Challenge: challenge,
			Present: present, TargetUID: targetUID, WorkloadScopeSHA256: scopeDigest})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("client identity chain is not singular")
			}
			return state.PeerCertificates[0].VerifyHostname("observer.test")
		}}
	server.StartTLS()
	defer server.Close()
	client, err := NewMTLSClient(roots, clientCert, "session.test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clock := &m106Clock{now: time.Date(2026, 9, 21, 5, 0, 0, 0, time.UTC)}
	store := &m106MemoryEvidence{}
	producer, err := New(client, store, m106StaticResolver{}, "process-epoch", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	producer.waitUntil = func(ctx context.Context, deadline time.Time) bool { clock.Set(deadline); return ctx.Err() == nil }
	policyEpoch := model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1}
	config := PrepareConfig{Policy: policyEpoch, Workload: workload,
		TargetUID: "old-pod-uid", TargetName: "old-pod", TargetTerminationGraceSeconds: 30,
		Old:         SessionEndpoint{URL: server.URL, SessionID: "old-session", Challenge: "challenge-old", TargetUID: "old-pod-uid", WorkloadScopeSHA256: scopeDigest},
		Replacement: SessionEndpoint{URL: server.URL, SessionID: "new-session", Challenge: "challenge-new", WorkloadScopeSHA256: scopeDigest}}
	if held, err := producer.CheckNoOperation(context.Background(), config.Old); err != nil || !held {
		t.Fatalf("no-operation positive control did not retain the exact old session: held=%t err=%v", held, err)
	}
	if len(producer.Drain(1)) != 0 {
		t.Fatal("no-operation control became an admitted rotate sample")
	}
	if err := producer.Prepare(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	rotated = true
	mu.Unlock()
	policy := model.Policy{Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "old-pod", UID: "old-pod-uid"}}
	request := actuator.Request{PolicyName: "policy", PolicyUID: "policy-uid", Namespace: "ns", Pod: "old-pod", TargetUID: "old-pod-uid", Action: model.ActionRotate}
	result := actuator.Result{Actuator: "native", Handler: string(model.ActionRotate), Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/old-pod"}}
	if !producer.RecordNativeRotate(policy, view, request, result, clock.Now()) {
		t.Fatal("coherent native rotate was not queued")
	}
	var deliveries []model.ScopedOutcomeDelivery
	for deadline := time.Now().Add(2 * time.Second); len(deliveries) == 0 && time.Now().Before(deadline); {
		deliveries = producer.Drain(4)
		time.Sleep(time.Millisecond)
	}
	if len(deliveries) != 1 || deliveries[0].Observation == nil || deliveries[0].Observation.Outcome != model.PersistenceRevoked {
		t.Fatalf("expected one explicit revoked result, got %+v", deliveries)
	}
	observation := *deliveries[0].Observation
	binding, ok := producer.AuthorizeObservation(observation)
	if !ok || binding.TargetUID != "old-pod-uid" || binding.ObservationNotBefore.Sub(binding.DispatchAcknowledgedAt) != 60*time.Second ||
		binding.ObservationDeadline.Sub(binding.DispatchAcknowledgedAt) != 65*time.Second {
		t.Fatalf("retained operation binding is wrong: %+v ok=%t", binding, ok)
	}
	store.mu.Lock()
	bundles := append([]EvidenceBundle(nil), store.bundles...)
	store.mu.Unlock()
	if len(bundles) != 1 || !reflect.DeepEqual(bundles[0].Observation, observation) || bundles[0].BeforeObservedAt.IsZero() ||
		bundles[0].BeforeObservedAt.After(bundles[0].Binding.DispatchAcknowledgedAt) || len(bundles[0].Before) == 0 || len(bundles[0].Action) == 0 || len(bundles[0].After) == 0 {
		t.Fatalf("raw evidence was not retained before authority: %+v", bundles)
	}
}

func TestPost25M106PreDispatchPeerProducesUnknownNotRevoked(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var rotated atomic.Bool
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		session := r.URL.Query().Get("session")
		present := session == "old" && !rotated.Load() || session == "new" && rotated.Load()
		status := http.StatusOK
		if !present {
			status = http.StatusGone
		}
		targetUID := "old-uid"
		if session == "new" {
			targetUID = "pre-dispatch-peer-uid"
		}
		body, _ := json.Marshal(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: session,
			Challenge: r.URL.Query().Get("challenge"), Present: present, TargetUID: targetUID, WorkloadScopeSHA256: scopeDigest})
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	acknowledgedAt := time.Date(2026, 9, 21, 5, 0, 0, 500_000_000, time.UTC)
	clock := &m106Clock{now: acknowledgedAt}
	resolver := m106TimedResolver{createdAt: acknowledgedAt.Add(-time.Second)}
	producer, err := newProducer(client, &m106MemoryEvidence{}, resolver, "epoch", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	producer.waitUntil = func(ctx context.Context, deadline time.Time) bool { clock.Set(deadline); return ctx.Err() == nil }
	epoch := model.PolicyEpoch{Namespace: "ns", Name: "p", UID: "u", Generation: 1}
	config := PrepareConfig{Policy: epoch, Workload: workload, TargetUID: "old-uid", TargetName: "old", TargetTerminationGraceSeconds: 30,
		Old:         SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "before", TargetUID: "old-uid", WorkloadScopeSHA256: scopeDigest},
		Replacement: SessionEndpoint{URL: "https://session.test/new", SessionID: "new", Challenge: "after", WorkloadScopeSHA256: scopeDigest}}
	if err := producer.Prepare(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	rotated.Store(true)
	policy := model.Policy{Namespace: "ns", PolicyName: "p", PolicyUID: "u", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "old", UID: "old-uid"}}
	request := actuator.Request{PolicyName: "p", PolicyUID: "u", Namespace: "ns", Pod: "old", TargetUID: "old-uid", Action: model.ActionRotate}
	result := actuator.Result{Actuator: "native", Handler: string(model.ActionRotate), Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/old"}}
	if !producer.RecordNativeRotate(policy, view, request, result, acknowledgedAt) {
		t.Fatal("coherent native rotate was not queued")
	}
	var deliveries []model.ScopedOutcomeDelivery
	for deadline := time.Now().Add(2 * time.Second); len(deliveries) == 0 && time.Now().Before(deadline); {
		deliveries = producer.Drain(1)
		time.Sleep(time.Millisecond)
	}
	if len(deliveries) != 1 || deliveries[0].Observation == nil || deliveries[0].Observation.Outcome != model.PersistenceUnknown {
		t.Fatalf("pre-dispatch peer was not retained as unknown: %+v", deliveries)
	}
	if _, ok := producer.AuthorizeObservation(*deliveries[0].Observation); !ok {
		t.Fatal("durably retained descriptive unknown was not authorized")
	}
}

func TestPost25M106BlockedEvidenceStoreNeverBlocksDispatch(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		session := r.URL.Query().Get("session")
		targetUID := "uid"
		if session == "new" {
			targetUID = "new-uid"
		}
		body, _ := json.Marshal(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: session, Challenge: r.URL.Query().Get("challenge"),
			Present: true, TargetUID: targetUID, WorkloadScopeSHA256: scopeDigest})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	clock := &m106Clock{now: time.Date(2026, 9, 21, 5, 0, 0, 0, time.UTC)}
	producer, err := newProducer(client, &m106MemoryEvidence{block: block, entered: entered}, m106StaticResolver{}, "epoch", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(block); producer.Close() }()
	producer.waitUntil = func(ctx context.Context, deadline time.Time) bool { clock.Set(deadline); return ctx.Err() == nil }
	epoch := model.PolicyEpoch{Namespace: "ns", Name: "p", UID: "u", Generation: 1}
	if err := producer.Prepare(context.Background(), PrepareConfig{Policy: epoch,
		Workload:  workload,
		TargetUID: "uid", TargetName: "pod", TargetTerminationGraceSeconds: 30,
		Old:         SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "before", TargetUID: "uid", WorkloadScopeSHA256: scopeDigest},
		Replacement: SessionEndpoint{URL: "https://session.test/new", SessionID: "new", Challenge: "after", WorkloadScopeSHA256: scopeDigest}}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	policy := model.Policy{Namespace: "ns", PolicyName: "p", PolicyUID: "u", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "pod", UID: "uid"}}
	request := actuator.Request{PolicyName: "p", PolicyUID: "u", Namespace: "ns", Pod: "pod", TargetUID: "uid", Action: model.ActionRotate}
	if !producer.RecordNativeRotate(policy, view, request, actuator.Result{Actuator: "native", Handler: "rotate", Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/pod"}}, clock.Now()) {
		t.Fatal("prepared coherent operation was not queued")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("producer hook waited for durable evidence")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach the blocking durable store")
	}
	if deliveries := producer.Drain(1); len(deliveries) != 0 {
		t.Fatalf("unretained evidence became admissible: %+v", deliveries)
	}
}

func TestPost25M106FailedEvidenceWriteNeverAuthorizesOutcome(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		session := r.URL.Query().Get("session")
		targetUID := "uid"
		if session == "new" {
			targetUID = "new-uid"
		}
		body, _ := json.Marshal(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: session, Challenge: r.URL.Query().Get("challenge"),
			Present: true, TargetUID: targetUID, WorkloadScopeSHA256: scopeDigest})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	clock := &m106Clock{now: time.Date(2026, 9, 21, 5, 0, 0, 0, time.UTC)}
	store, err := NewDirectoryEvidenceStore(filepath.Join(t.TempDir(), "evidence"), 2, maxEvidenceBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	realCreate := store.createTemp
	store.createTemp = func(dir, pattern string) (evidenceTempFile, error) {
		file, err := realCreate(dir, pattern)
		if err != nil {
			return nil, err
		}
		return m106ShortEvidenceFile{evidenceTempFile: file}, nil
	}
	producer, err := newProducer(client, store, m106StaticResolver{}, "epoch", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	producer.waitUntil = func(ctx context.Context, deadline time.Time) bool { clock.Set(deadline); return ctx.Err() == nil }
	epoch := model.PolicyEpoch{Namespace: "ns", Name: "p", UID: "u", Generation: 1}
	config := PrepareConfig{Policy: epoch, Workload: workload, TargetUID: "uid", TargetName: "pod", TargetTerminationGraceSeconds: 30,
		Old:         SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "before", TargetUID: "uid", WorkloadScopeSHA256: scopeDigest},
		Replacement: SessionEndpoint{URL: "https://session.test/new", SessionID: "new", Challenge: "after", WorkloadScopeSHA256: scopeDigest}}
	if err := producer.Prepare(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{Namespace: "ns", PolicyName: "p", PolicyUID: "u", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "pod", UID: "uid"}}
	request := actuator.Request{PolicyName: "p", PolicyUID: "u", Namespace: "ns", Pod: "pod", TargetUID: "uid", Action: model.ActionRotate}
	result := actuator.Result{Actuator: "native", Handler: string(model.ActionRotate), Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/pod"}}
	contradictory := result
	contradictory.NoEffect = actuator.NoEffectRefused
	if producer.RecordNativeRotate(policy, view, request, contradictory, clock.Now()) {
		t.Fatal("contradictory emitted/no-effect receipt was queued")
	}
	if !producer.RecordNativeRotate(policy, view, request, result, clock.Now()) {
		t.Fatal("coherent prepared operation was not queued")
	}
	var deliveries []model.ScopedOutcomeDelivery
	for deadline := time.Now().Add(2 * time.Second); len(deliveries) == 0 && time.Now().Before(deadline); {
		deliveries = producer.Drain(4)
		time.Sleep(time.Millisecond)
	}
	if len(deliveries) != 1 || deliveries[0].Observation != nil || deliveries[0].Disposition != model.PersistenceDispositionUnavailable {
		t.Fatalf("failed evidence write became an observation: %+v", deliveries)
	}
	for evidenceID := range producer.allowed {
		t.Fatalf("failed evidence write created authority entry %q", evidenceID)
	}
	engine := decision.NewCoverageEngine()
	if err := engine.SetOwnerEpoch(epoch, true); err != nil {
		t.Fatal(err)
	}
	engine.RecordScopedOutcomeUnavailable(epoch, deliveries[0].Reason)
	report, ok := engine.ScopedOutcomeReportFor(epoch.Owner())
	if !ok || report.ReplayEntries != 0 || len(report.Cohorts) != 0 || report.Disposition != model.PersistenceDispositionNoProducer {
		t.Fatalf("failed durable evidence entered reporting authority: %+v ok=%t", report, ok)
	}
}

func TestPost25M106MissedWindowPreservesActualTimesAsCensored(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	probeCalls := 0
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		probeCalls++
		if probeCalls == 1 {
			body, _ := json.Marshal(SessionResponse{SchemaVersion: SessionResponseSchemaV1, SessionID: "old", Challenge: "before",
				Present: true, TargetUID: "uid", WorkloadScopeSHA256: scopeDigest})
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
		}
		return nil, errors.New("late observation must not probe")
	}), Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	clock := &m106Clock{now: time.Date(2026, 9, 21, 5, 0, 0, 0, time.UTC)}
	producer, err := newProducer(client, &m106MemoryEvidence{}, m106StaticResolver{}, "epoch", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	producer.waitUntil = func(ctx context.Context, notBefore time.Time) bool {
		clock.Set(notBefore.Add(6 * time.Second))
		return ctx.Err() == nil
	}
	epoch := model.PolicyEpoch{Namespace: "ns", Name: "p", UID: "u", Generation: 1}
	config := PrepareConfig{Policy: epoch, Workload: workload, TargetUID: "uid", TargetName: "pod", TargetTerminationGraceSeconds: 30,
		Old:         SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "before", TargetUID: "uid", WorkloadScopeSHA256: scopeDigest},
		Replacement: SessionEndpoint{URL: "https://session.test/new", SessionID: "new", Challenge: "after", WorkloadScopeSHA256: scopeDigest}}
	if err := producer.Prepare(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	acknowledged := clock.Now()
	policy := model.Policy{Namespace: "ns", PolicyName: "p", PolicyUID: "u", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "pod", UID: "uid"}}
	request := actuator.Request{PolicyName: "p", PolicyUID: "u", Namespace: "ns", Pod: "pod", TargetUID: "uid", Action: model.ActionRotate}
	result := actuator.Result{Actuator: "native", Handler: string(model.ActionRotate), Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/pod"}}
	if !producer.RecordNativeRotate(policy, view, request, result, acknowledged) {
		t.Fatal("coherent prepared operation was not queued")
	}
	var deliveries []model.ScopedOutcomeDelivery
	for deadline := time.Now().Add(2 * time.Second); len(deliveries) == 0 && time.Now().Before(deadline); {
		deliveries = producer.Drain(4)
		time.Sleep(time.Millisecond)
	}
	if len(deliveries) != 1 || deliveries[0].Observation == nil {
		t.Fatalf("missing late censored delivery: %+v", deliveries)
	}
	observation := deliveries[0].Observation
	wantActual := acknowledged.Add(66 * time.Second)
	if observation.Outcome != model.PersistenceCensored || !observation.ObservationStart.Equal(wantActual) ||
		!observation.ObservationEnd.Equal(wantActual) || probeCalls != 1 {
		t.Fatalf("missed horizon fabricated time or made an after-dispatch probe: observation=%+v calls=%d", observation, probeCalls)
	}
}

func TestPost25M106ProbeRejectsNullPresence(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := []byte(`{"schemaVersion":"phorvex.synthetic-process-session-response.v1","sessionID":"old","challenge":"challenge","present":null,"targetUID":"uid","workloadScopeSHA256":"` + scopeDigest + `"}`)
		return &http.Response{StatusCode: http.StatusGone, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
	producer := &Producer{client: client}
	_, err = producer.probe(context.Background(), SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "challenge", TargetUID: "uid", WorkloadScopeSHA256: scopeDigest})
	if err == nil || err.Error() != "synthetic session response presence is not a boolean" {
		t.Fatalf("null presence was not rejected: %v", err)
	}
}

func TestPost25M106ProbeRejectsInvalidUTF8BeforeJSONNormalization(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	scopeDigest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := []byte(`{"schemaVersion":"phorvex.synthetic-process-session-response.v1","sessionID":"old","challenge":"challenge","present":true,"targetUID":"uid","workloadScopeSHA256":"` + scopeDigest + `"}`)
		body = bytes.Replace(body, []byte("challenge\""), []byte{'c', 'h', 0xff, '"'}, 1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
	producer := &Producer{client: client}
	_, err = producer.probe(context.Background(), SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "challenge", TargetUID: "uid", WorkloadScopeSHA256: scopeDigest})
	if err == nil || err.Error() != "synthetic session response is not valid UTF-8" {
		t.Fatalf("invalid UTF-8 was normalized before refusal: %v", err)
	}
}

func TestPost25M106ProbeRejectsOversizedAndDuplicateResponses(t *testing.T) {
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "owner"}
	digest, err := workload.Digest()
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"schemaVersion":"phorvex.synthetic-process-session-response.v1","sessionID":"old","challenge":"challenge","present":true,"targetUID":"uid","workloadScopeSHA256":"` + digest + `"}`
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "oversized", body: bytes.Repeat([]byte("x"), maxHTTPBodyBytes+1)},
		{name: "duplicate", body: []byte(strings.Replace(valid, `"present":true`, `"present":true,"present":false`, 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: m106RoundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(tc.body)), Header: make(http.Header), Request: r}, nil
			})}
			producer := &Producer{client: client}
			if _, err := producer.probe(context.Background(), SessionEndpoint{URL: "https://session.test/old", SessionID: "old", Challenge: "challenge", TargetUID: "uid", WorkloadScopeSHA256: digest}); err == nil {
				t.Fatal("malicious response was accepted")
			}
		})
	}
}

type m106RoundTripFunc func(*http.Request) (*http.Response, error)

func (f m106RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func m106CA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m106-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ca, key, pool
}

func m106Leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pemEncode("CERTIFICATE", raw), pemEncodeEC(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemEncode(kind string, raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: raw})
}
func pemEncodeEC(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncode("EC PRIVATE KEY", raw)
}
