package runner

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
)

type m100BlockingReader struct{}

func (m100BlockingReader) Get(ctx context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	<-ctx.Done()
	return ctx.Err()
}

func (m100BlockingReader) List(ctx context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	<-ctx.Done()
	return ctx.Err()
}

type m100BlockingLedger struct {
	base      losshistory.Ledger
	entered   chan struct{}
	release   chan struct{}
	done      chan struct{}
	enterOnce sync.Once
}

func (l *m100BlockingLedger) ContainsExact(string, string, string, string) bool { return false }

func (l *m100BlockingLedger) Put(record model.AdmittedLossV1) error {
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.release
	err := l.base.Put(record)
	close(l.done)
	return err
}

func (l *m100BlockingLedger) Query(policyUID, ownerUID string) losshistory.Result {
	return l.base.Query(policyUID, ownerUID)
}

func m100OwnerRef(kind, name, uid string) metav1.OwnerReference {
	yes := true
	return metav1.OwnerReference{APIVersion: "apps/v1", Kind: kind, Name: name, UID: types.UID(uid), Controller: &yes}
}

func m100Boundary(at time.Time) *admissionv1.MutatingWebhookConfiguration {
	fail := admissionv1.Fail
	path := "/stamp-amtd-r6security-com-v1beta1-securityevent"
	return &admissionv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "loss-boundary", UID: "mwc-uid", ResourceVersion: "7", CreationTimestamp: metav1.NewTime(at),
		Annotations: map[string]string{disclosure.BoundaryContractAnnotation: disclosure.BoundaryContract}},
		Webhooks: []admissionv1.MutatingWebhook{{Name: "stamp-completed-disclosures.phorvex.ai", FailurePolicy: &fail,
			MatchConditions: []admissionv1.MatchCondition{{Name: "completed", Expression: losshistory.CompletedDisclosureMatch}},
			ClientConfig:    admissionv1.WebhookClientConfig{CABundle: []byte("ca"), Service: &admissionv1.ServiceReference{Namespace: "system", Name: "webhook", Path: &path}},
			Rules:           []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{"amtd.r6security.com"}, APIVersions: []string{"v1beta1"}, Resources: []string{"securityevents"}}}},
		}},
	}
}

func m100PayloadAndEvent(t *testing.T, now time.Time) (model.CompletedDisclosureV1, model.SecurityEventInfo) {
	t.Helper()
	digest := strings.Repeat("a", 64)
	p := model.CompletedDisclosureV1{SchemaVersion: model.CompletedDisclosureSchemaV1, EvidenceID: "copy-1",
		PolicyEpoch:         model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 3},
		DecisionAsset:       model.DecisionAssetIdentity{Namespace: "ns", Name: "old-pod", TargetUID: "old-uid"},
		ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "old-rs", UID: "old-rs-uid"},
		StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "dep-uid"},
		ProtectedScope:      model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/customer-row", Version: "data-v1", Property: "confidentiality"},
		Classification: model.DisclosureClassification{RuleVersion: "rule-v1", RuleDigest: digest,
			ObserverClass: model.CompletedDisclosureClass, ObserverIdentity: "system:serviceaccount:ns:observer"},
		Observation: model.DisclosureObservation{StartedAt: now.Add(-2 * time.Second), CompletedAt: now.Add(-time.Second), StatusCode: 200, ExpectedBytes: 10, ObservedBytes: 10, ReachedEOF: true, ExpectedSHA256: digest, ObservedSHA256: digest}, Synthetic: true}
	created := now.Add(-500 * time.Millisecond)
	p.Observation.CompletedAt = created.Add(100 * time.Millisecond)
	raw, _, err := disclosure.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, model.SecurityEventInfo{Name: "loss-event", UID: "event-uid", CreatedAt: created,
		CreatorIdentity: "system:serviceaccount:ns:observer", Type: model.CompletedDisclosureRuleType, ThreatLevel: "high", Source: model.CompletedDisclosureSource,
		Description: model.CompletedDisclosureDescription, ResolvedTargets: []string{"ns/old-pod"}, CompletedDisclosureRaw: raw,
		CompletedDisclosureAdmittedAt:        created.Add(250 * time.Millisecond).Format(time.RFC3339Nano),
		CompletedDisclosureAdmissionContract: disclosure.BoundaryContract}
}

func TestM100AdmittedHistorySurvivesPodAndReplicaSetReplacement(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = admissionv1.AddToScheme(scheme)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	oldRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-rs", UID: "old-rs-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("Deployment", "app", "dep-uid")}}}
	oldPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-pod", UID: "old-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("ReplicaSet", "old-rs", "old-rs-uid")}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, oldRS, oldPod, m100Boundary(now.Add(-time.Minute))).Build()
	store, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Local: &inprocess.Services{}, BoundaryReader: c, LossHistory: store}
	observer := eventtrust.NewTrustedDetectors([]string{"ns/observer"})
	eventtrust.ConfigureCompletedDisclosureTrust(observer)
	t.Cleanup(func() { eventtrust.ConfigureCompletedDisclosureTrust(eventtrust.NewTrustedDetectors(nil)) })
	_, event := m100PayloadAndEvent(t, now)
	// Admission attested generation 3. A same-UID policy update before the first
	// ledger tick must not erase the completed observation.
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 4, TickID: "tick"}
	if gaps := m.admitCompletedDisclosures(context.Background(), []model.SecurityEventInfo{event}, policy, now); len(gaps) != 0 {
		t.Fatalf("valid admission gaps=%v", gaps)
	}
	if err := c.Delete(context.Background(), oldPod); err != nil {
		t.Fatal(err)
	}
	newRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "new-rs", UID: "new-rs-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("Deployment", "app", "dep-uid")}}}
	newPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "new-pod", UID: "new-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("ReplicaSet", "new-rs", "new-rs-uid")}}}
	if err := c.Create(context.Background(), newRS); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), newPod); err != nil {
		t.Fatal(err)
	}
	decision := model.Decision{Tenant: "tenant", Namespace: "ns", Pod: "new-pod"}
	histories := m.representationHistoryInputs(context.Background(), []model.Decision{decision}, map[string]string{"ns/new-pod": "new-uid"}, policy, nil)
	snapshot := representationSnapshotV1(decision, policy, "new-uid", model.ClaimScope{}, nil, histories["ns/new-pod"])
	report := representation.Build(snapshot)
	if report.Version != representation.VersionCompletedDisclosure || report.KnownLossCount != 1 || len(report.AlreadyLost) != 1 || report.LossAssessment != "available" {
		t.Fatalf("replacement lost retained evidence: %+v", report)
	}
	w := report.AlreadyLost[0].Witnesses[0]
	if w.DecisionAsset == nil || w.DecisionAsset.Name != "old-pod" || w.DecisionAsset.TargetUID != "old-uid" ||
		w.StableWorkloadOwner == nil || w.StableWorkloadOwner.UID != "dep-uid" || w.Scope.Version != "data-v1" {
		t.Fatalf("witness provenance changed: %+v", w)
	}
	if report.Snapshot.Scope.Version != "new-uid" || report.AlreadyLost[0].Scope.Asset == report.Snapshot.Scope.Asset {
		t.Fatalf("protected data scope collapsed into replacement Pod scope: %+v", report)
	}
	if report.AlreadyLost[0].Witnesses[0].PolicyEpoch.Generation != 3 {
		t.Fatalf("historical admission epoch was rewritten to current generation: %+v", report.AlreadyLost[0].Witnesses[0].PolicyEpoch)
	}
	decision.Selected = true
	appendRepresentation(&decision, snapshot)
	var auditBytes bytes.Buffer
	audit.New(logr.Discard(), &auditBytes).Record(decision)
	if !strings.Contains(auditBytes.String(), model.AdmittedLossSchemaV1) || !strings.Contains(auditBytes.String(), "event-uid") ||
		strings.Contains(auditBytes.String(), "synthetic-canary") {
		t.Fatalf("typed retained history did not reach bounded audit row: %s", auditBytes.String())
	}
	bad := snapshot
	bad.History = append([]model.RetainedLoss(nil), snapshot.History...)
	badWitness := bad.History[0].Witnesses[0]
	badClass := *badWitness.Classification
	badClass.ObserverIdentity = "system:serviceaccount:ns:other"
	badWitness.Classification = &badClass
	bad.History[0].Witnesses = []model.LossWitness{badWitness}
	if malformed := representation.Build(bad); malformed.KnownLossCount != 0 || len(malformed.AlreadyLost) != 0 {
		t.Fatalf("observer identity mismatch counted as retained loss: %+v", malformed)
	}
	badTime := snapshot
	badTime.History = append([]model.RetainedLoss(nil), snapshot.History...)
	timeWitness := badTime.History[0].Witnesses[0]
	timeWitness.AdmissionTime = ""
	badTime.History[0].Witnesses = []model.LossWitness{timeWitness}
	if malformed := representation.Build(badTime); malformed.KnownLossCount != 0 || len(malformed.AlreadyLost) != 0 {
		t.Fatalf("missing admission time counted as retained loss: %+v", malformed)
	}
	otherPolicy := policy
	otherPolicy.PolicyUID = "recreated-policy"
	other := m.representationHistoryInputs(context.Background(), []model.Decision{decision}, map[string]string{"ns/new-pod": "new-uid"}, otherPolicy, nil)
	if len(other["ns/new-pod"].result.Records) != 0 {
		t.Fatal("recreated policy inherited retained loss")
	}
	otherTenant := policy
	otherTenant.Tenant = "new-tenant"
	separated := m.representationHistoryInputs(context.Background(), []model.Decision{decision}, map[string]string{"ns/new-pod": "new-uid"}, otherTenant, nil)
	if len(separated["ns/new-pod"].result.Records) != 0 || len(separated["ns/new-pod"].gaps) == 0 {
		t.Fatalf("old tenant history silently joined current scope: %+v", separated["ns/new-pod"])
	}

	// A generic already-lost-looking event does not enter the dedicated store.
	generic := model.SecurityEventInfo{Name: "raw", UID: "raw-uid", CreatorIdentity: event.CreatorIdentity, Outcomes: []model.ProtectedOutcome{{LossState: "already-lost"}}}
	if gaps := m.admitCompletedDisclosures(context.Background(), []model.SecurityEventInfo{generic}, policy, now); len(gaps) != 0 {
		t.Fatalf("generic event changed dedicated history: %v", gaps)
	}
	if got := store.Query(policy.PolicyUID, "dep-uid"); len(got.Records) != 1 {
		t.Fatalf("generic event admitted: %+v", got)
	}
}

func TestM100OptionalHistoryTimeoutDoesNotDisableSelectedActuation(t *testing.T) {
	store, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	fakeActuator := &dispatchFakeActuator{emit: true}
	m := &Manager{Local: &inprocess.Services{Actuator: fakeActuator}, LossHistory: store, LossHistoryReader: m100BlockingReader{}, LossHistoryReadTimeout: 10 * time.Millisecond,
		Log: logr.Discard()}
	decisions := tracedSelectedDecision()
	decisions[0].Tenant = "tenant"
	versions := map[string]string{"ns/p1": "uid-1"}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
		MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	snapshots, histories, complete := m.prepareRepresentationSnapshots(ctx, decisions, policy, versions, model.ClaimScope{}, nil, nil, time.Now())
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond || !complete || len(snapshots) != 1 ||
		histories["ns/p1"].result.Status != "unavailable" || ctx.Err() != nil {
		t.Fatalf("optional history consumed core tick: elapsed=%v complete=%t snapshots=%d history=%+v ctx=%v", elapsed, complete, len(snapshots), histories, ctx.Err())
	}
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "uid-1", Ready: true, DesiredReplicas: 2, ReadyReplicas: 2}}}
	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, policy, decisions, views); got != 1 || fakeActuator.calls != 1 || !decisions[0].Actuated {
		t.Fatalf("optional history timeout disabled safe action: got=%d calls=%d decision=%+v", got, fakeActuator.calls, decisions[0])
	}

	// A configured but unavailable store at startup is represented by nil and
	// likewise leaves unrelated dispatch available.
	m.LossHistory = nil
	decisions = tracedSelectedDecision()
	decisions[0].Tenant = "tenant"
	if _, histories, complete := m.prepareRepresentationSnapshots(ctx, decisions, policy, versions, model.ClaimScope{}, nil, nil, time.Now()); !complete || histories != nil {
		t.Fatalf("unavailable store changed core snapshot completion: complete=%t histories=%v", complete, histories)
	}
	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, policy, decisions, views); got != 1 || fakeActuator.calls != 2 {
		t.Fatalf("unavailable store disabled safe action: got=%d calls=%d", got, fakeActuator.calls)
	}
}

func TestM100BlockedDurableRetentionDoesNotDisableSelectedActuation(t *testing.T) {
	now := time.Unix(900, 0).UTC()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = admissionv1.AddToScheme(scheme)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-rs", UID: "old-rs-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("Deployment", "app", "dep-uid")}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-pod", UID: "old-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("ReplicaSet", "old-rs", "old-rs-uid")}}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, m100Boundary(now.Add(-time.Minute))).Build()
	base, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	blocking := &m100BlockingLedger{base: base, entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	fakeActuator := &dispatchFakeActuator{emit: true}
	m := &Manager{Local: &inprocess.Services{Actuator: fakeActuator}, BoundaryReader: reader, LossHistoryReader: reader, LossHistory: blocking, LossHistoryReadTimeout: 10 * time.Millisecond,
		Log: logr.Discard()}
	eventtrust.ConfigureCompletedDisclosureTrust(eventtrust.NewTrustedDetectors([]string{"ns/observer"}))
	t.Cleanup(func() { eventtrust.ConfigureCompletedDisclosureTrust(eventtrust.NewTrustedDetectors(nil)) })
	_, event := m100PayloadAndEvent(t, now)
	decision := tracedSelectedDecision()
	decision[0].Namespace, decision[0].Pod, decision[0].Tenant = "ns", "old-pod", "tenant"
	versions := map[string]string{"ns/old-pod": "old-uid"}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 4,
		MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, histories, complete := m.prepareRepresentationSnapshots(ctx, decision, policy, versions, model.ClaimScope{}, nil, []model.SecurityEventInfo{event}, now)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond || !complete || histories["ns/old-pod"].result.Status != "unavailable" || ctx.Err() != nil {
		t.Fatalf("blocked durable store consumed core tick: elapsed=%v complete=%t history=%+v ctx=%v", elapsed, complete, histories, ctx.Err())
	}
	select {
	case <-blocking.entered:
	default:
		t.Fatal("producer did not reach the durable Put boundary")
	}
	views := map[string]*model.WorkloadView{"ns/old-pod": {Pod: model.Pod{Namespace: "ns", Name: "old-pod", UID: "old-uid", Ready: true, DesiredReplicas: 2, ReadyReplicas: 2}}}
	if got := actuateWithBoundary(t, m, ctx, &policyEntry{namespace: "ns"}, policy, decision, views); got != 1 || fakeActuator.calls != 1 || !decision[0].Actuated {
		t.Fatalf("blocked durable store disabled safe action: got=%d calls=%d decision=%+v", got, fakeActuator.calls, decision[0])
	}
	close(blocking.release)
	select {
	case <-blocking.done:
	case <-time.After(time.Second):
		t.Fatal("released durable store worker did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for {
		m.lossHistoryWorker.mu.Lock()
		busy := m.lossHistoryWorker.busy
		m.lossHistoryWorker.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("released durable store coordinator remained busy")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestM100AdmissionRejectsUnboundCurrentState(t *testing.T) {
	now := time.Unix(800, 0).UTC()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = admissionv1.AddToScheme(scheme)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-rs", UID: "old-rs-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("Deployment", "app", "dep-uid")}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-pod", UID: "old-uid", OwnerReferences: []metav1.OwnerReference{m100OwnerRef("ReplicaSet", "old-rs", "old-rs-uid")}}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, m100Boundary(now.Add(-time.Minute))).Build()
	eventtrust.ConfigureCompletedDisclosureTrust(eventtrust.NewTrustedDetectors([]string{"ns/observer", "ns/other"}))
	t.Cleanup(func() { eventtrust.ConfigureCompletedDisclosureTrust(eventtrust.NewTrustedDetectors(nil)) })
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 3}

	cases := []struct {
		name   string
		mutate func(*model.CompletedDisclosureV1, *model.SecurityEventInfo)
		gap    string
	}{
		{"observer identity", func(p *model.CompletedDisclosureV1, _ *model.SecurityEventInfo) {
			p.Classification.ObserverIdentity = "system:serviceaccount:ns:other"
		}, "completed-disclosure-observer-identity-mismatch"},
		{"event target", func(_ *model.CompletedDisclosureV1, e *model.SecurityEventInfo) { e.ResolvedTargets[0] = "ns/other" }, "completed-disclosure-event-binding-mismatch"},
		{"event timestamp", func(_ *model.CompletedDisclosureV1, e *model.SecurityEventInfo) { e.TimestampMissing = true }, "completed-disclosure-event-identity-unavailable"},
		{"observation after event", func(p *model.CompletedDisclosureV1, e *model.SecurityEventInfo) {
			p.Observation.CompletedAt = e.CreatedAt.Add(time.Second)
		}, "completed-disclosure-observation-time-unbound"},
		{"admission contract", func(_ *model.CompletedDisclosureV1, e *model.SecurityEventInfo) {
			e.CompletedDisclosureAdmissionContract = ""
		}, "completed-disclosure-observation-time-unbound"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, event := m100PayloadAndEvent(t, now)
			tc.mutate(&payload, &event)
			raw, _, err := disclosure.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			event.CompletedDisclosureRaw = raw
			store, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
			if err != nil {
				t.Fatal(err)
			}
			m := &Manager{Local: &inprocess.Services{}, BoundaryReader: reader, LossHistory: store}
			gaps := m.admitCompletedDisclosures(context.Background(), []model.SecurityEventInfo{event}, policy, now)
			if len(gaps) != 1 || gaps[0] != tc.gap {
				t.Fatalf("gaps=%v want=%s", gaps, tc.gap)
			}
			if got := store.Query(policy.PolicyUID, "dep-uid"); len(got.Records) != 0 {
				t.Fatalf("rejected disclosure persisted: %+v", got)
			}
		})
	}
}
