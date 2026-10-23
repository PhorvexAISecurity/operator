package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/console"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func m010KVView(uid string) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: "p1", UID: uid, ModelID: "served-model",
			Ready: true, DesiredReplicas: 1, ReadyReplicas: 1,
		},
		HasEventEvidence: true,
	}
}

func m010Entry() *policyEntry {
	return &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "policy-uid", namespace: "ns", spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}}}
}

func m010ServingPolicy() *v1alpha1.PhorvexPolicy {
	return &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid", ResourceVersion: "2"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionKVReset)}}}}
}

// This is the end-to-end producer counterexample from M-10: the real native
// kv-reset handler proves that no serving endpoint was reachable, the runner
// retains that closed refusal, and audit/history keep it even without relying
// on a nested decision trace.
func TestM010NativeUnavailableRefusalSurvivesRunnerAuditAndHistory(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1", UID: types.UID("pod-uid"), ResourceVersion: "1", Labels: map[string]string{"app": "demo"}, Annotations: map[string]string{"phorvex.ai/serving-port": strconv.Itoa(port)}},
		Status:     corev1.PodStatus{PodIP: "127.0.0.1"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, m010ServingPolicy()).Build()
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	m := &Manager{Local: &inprocess.Services{Actuator: native}, Intents: exposure.NewIntents(), Log: logr.Discard()}
	view := m010KVView("pod-uid")
	decisions := []model.Decision{{
		Tenant: "tenant", Namespace: "ns", Pod: "p1", Action: model.ActionKVReset,
		Selected: true, Feasible: true, Engine: "p1-coverage", CoverageValue: 3.25, CoveredWeight: 2.75,
	}}
	policy := model.Policy{Tenant: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	if got := actuateWithBoundary(t, m, context.Background(), m010Entry(), policy, decisions, map[string]*model.WorkloadView{"ns/p1": view}); got != 0 {
		t.Fatalf("actuated = %d", got)
	}
	d := decisions[0]
	if d.Actuated || d.DispatchOutcome != model.DispatchRefused || d.DispatchReason != "definite-no-effect-refusal" {
		t.Fatalf("runner result = %+v", d)
	}
	if r := m.Failures.at[failureKey{policy.Owner(), "ns", "pod-uid", model.ActionKVReset}]; r.consecutive != 1 {
		t.Fatalf("definite refusal did not enter bounded feedback: %+v", r)
	}

	var sink bytes.Buffer
	var lines []string
	logger := funcr.New(func(prefix, args string) { lines = append(lines, prefix+" "+args) }, funcr.Options{})
	a := audit.New(logger, &sink)
	if err := a.Record(d); err != nil {
		t.Fatal(err)
	}
	var rec audit.Record
	if err := json.Unmarshal(bytes.TrimSpace(sink.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.DispatchOutcome != model.DispatchRefused || rec.DispatchReason != "definite-no-effect-refusal" ||
		rec.CoverageValue != 3.25 || rec.CoveredWeight != 2.75 || rec.CoverageBasis != "modeled-selection-opportunity" {
		t.Fatalf("retained record = %+v", rec)
	}
	owner := console.ToOwnerEvent(rec)
	if owner.OutcomeEvidence != "not-emitted" || !strings.Contains(owner.Why, "definitely refused") {
		t.Fatalf("history projection = %+v", owner)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{`"actuated"=false`, `"dispatchOutcome"="refused-no-effect"`, `"dispatchReason"="definite-no-effect-refusal"`, `"coverageBasis"="modeled-selection-opportunity"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("structured decision log missing %s: %s", want, joined)
		}
	}
}

func TestM010NativeLoopbackSuccessKeepsModeledCoverageQualified(t *testing.T) {
	requestSeen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1", UID: types.UID("pod-uid"), ResourceVersion: "1", Labels: map[string]string{"app": "demo"}, Annotations: map[string]string{"phorvex.ai/serving-port": portText}},
		Status:     corev1.PodStatus{PodIP: "127.0.0.1"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		pod, m010ServingPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", UID: "ns-uid", ResourceVersion: "1"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid", ResourceVersion: "1"}},
	).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if _, ok := obj.(*corev1.ConfigMap); ok {
			obj.SetUID(types.UID("created-" + obj.GetName()))
		}
		return c.Create(ctx, obj, opts...)
	}}).Build()
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	native.JournalNamespace = "operator"
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	m := &Manager{Local: &inprocess.Services{Actuator: native}, Intents: exposure.NewIntents(), Log: logr.Discard()}
	view := m010KVView("pod-uid")
	decisions := []model.Decision{{
		Namespace: "ns", Pod: "p1", Action: model.ActionKVReset, Selected: true, Feasible: true,
		Engine: "p1-coverage", CoverageValue: 4.5, CoveredWeight: 3.5,
		Trace: &model.DecisionTraceV2{DispatchOutcome: model.DispatchNotAttempted, DispatchReason: "pending-dispatch"},
	}}
	policy := model.Policy{Tenant: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", TickID: "m010-loopback-tick-1", EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	if got := actuateWithBoundary(t, m, context.Background(), m010Entry(), policy, decisions, map[string]*model.WorkloadView{"ns/p1": view}); got != 1 {
		t.Fatalf("actuations = %d; decision=%+v", got, decisions[0])
	}
	var request string
	select {
	case request = <-requestSeen:
	default:
	}
	if request != "POST /reset_prefix_cache" || !decisions[0].Actuated || decisions[0].DispatchOutcome != model.DispatchEmitted {
		t.Fatalf("request=%q decision=%+v", request, decisions[0])
	}
	rec := audit.ToRecord(decisions[0])
	if rec.CoverageValue != 4.5 || rec.CoveredWeight != 3.5 || rec.CoverageBasis != "modeled-selection-opportunity" {
		t.Fatalf("modeled selection explanation changed: %+v", rec)
	}

	// A later real decision starts from the acknowledged epoch. After the serving
	// endpoint disappears, its definite pre-send refusal must replace every
	// success/native field from the first call.
	server.Close()
	current := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	value, present := current.Annotations["phorvex.ai/kv-reset-epoch"]
	view.Pod.KVResetEpoch = model.OwnedValue{Present: present, Value: value}
	policy.TickID = "m010-loopback-tick-2"
	if got := actuateWithBoundary(t, m, context.Background(), m010Entry(), policy, decisions, map[string]*model.WorkloadView{"ns/p1": view}); got != 0 {
		t.Fatalf("closed endpoint actuations = %d", got)
	}
	d := decisions[0]
	if d.Actuated || d.DispatchOutcome != model.DispatchRefused || d.DispatchReason != "definite-no-effect-refusal" ||
		d.Trace.DispatchOutcome != model.DispatchRefused || d.Trace.DispatchReason != "definite-no-effect-refusal" ||
		d.Handler != string(model.ActionKVReset) || len(d.ObjectsTouched) != 0 || d.RollbackRef != "" || d.MutationKind != "none" || d.Phoenix != nil {
		t.Fatalf("refusal retained prior success evidence: %+v", d)
	}
}

func TestM010ExplicitNilErrorRefusalUsesReservedAlternativeOnce(t *testing.T) {
	ce, pol, views, ds := m019Scenario(t)
	alt, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", ds[0].Action)
	if !ok {
		t.Fatal("reserved alternative absent")
	}
	hands := &m019Hands{result: actuator.Result{NoEffect: actuator.NoEffectRefused}}
	m := &Manager{Local: &inprocess.Services{Actuator: hands, Optimizer: ce}, Intents: exposure.NewIntents(), Log: logr.Discard()}
	if got := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{"ns/pod": views[0]}); got != 1 {
		t.Fatalf("actuations = %d, calls = %v", got, hands.calls)
	}
	if len(hands.calls) != 2 || hands.calls[0] == hands.calls[1] || len(m.fallbackDecisions) != 1 {
		t.Fatalf("alternative was not single and distinct: calls=%v fallback=%+v", hands.calls, m.fallbackDecisions)
	}
	if ds[0].DispatchOutcome != model.DispatchRefused || ds[0].DispatchReason != "definite-no-effect-refusal" {
		t.Fatalf("primary refusal = %+v", ds[0])
	}
	fallback := m.fallbackDecisions[0]
	if fallback.Action != alt.Action || fallback.DispatchOutcome != model.DispatchEmitted || !fallback.Actuated ||
		fallback.CoverageValue != alt.Coverage || fallback.CoveredWeight != alt.Marginal {
		t.Fatalf("fallback evidence = %+v, reserved=%+v", fallback, alt)
	}
}

type m010FixedHands struct {
	result actuator.Result
	err    error
	calls  int
}

func (*m010FixedHands) Name() string                                              { return "native" }
func (*m010FixedHands) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (*m010FixedHands) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (h *m010FixedHands) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	h.calls++
	return h.result, h.err
}

func TestM010RefusalCooldownExpirySuccessAndTargetIdentity(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	hands := &m010FixedHands{result: actuator.Result{NoEffect: actuator.NoEffectRefused}}
	m := &Manager{Local: &inprocess.Services{Actuator: hands}, Intents: exposure.NewIntents(), Log: logr.Discard(), FailureNow: func() time.Time { return now }}
	pol := model.Policy{Tenant: "tenant", PolicyUID: "policy-uid", EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	view := m010KVView("uid-one")
	viewMap := map[string]*model.WorkloadView{"ns/p1": view}
	newDecision := func() []model.Decision {
		return []model.Decision{{Namespace: "ns", Pod: "p1", Action: model.ActionKVReset, Selected: true, Feasible: true}}
	}
	for i := 0; i < 2; i++ {
		ds := newDecision()
		if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, viewMap); n != 0 || ds[0].DispatchOutcome != model.DispatchRefused {
			t.Fatalf("refusal %d = n=%d %+v", i, n, ds[0])
		}
		now = now.Add(10 * time.Second)
	}
	key := failureKey{pol.Owner(), "ns", "uid-one", model.ActionKVReset}
	if why, excluded := m.Failures.exclusion(key, now); !excluded || !strings.Contains(why, "consecutive=2") {
		t.Fatalf("cooldown absent: %q %+v", why, m.Failures.at[key])
	}
	if _, excluded := m.Failures.exclusion(key, now.Add(31*time.Second)); excluded {
		t.Fatal("expired cooldown remained active")
	}

	view.Pod.UID = "uid-two"
	ds := newDecision()
	actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, viewMap)
	if m.Failures.at[failureKey{pol.Owner(), "ns", "uid-two", model.ActionKVReset}].consecutive != 1 ||
		m.Failures.at[key].consecutive != 2 {
		t.Fatalf("replacement target inherited failure state: %+v", m.Failures.at)
	}

	hands.result = actuator.Result{Emitted: true}
	ds = newDecision()
	if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, viewMap); n != 1 {
		t.Fatalf("success actuations = %d", n)
	}
	if _, present := m.Failures.at[failureKey{pol.Owner(), "ns", "uid-two", model.ActionKVReset}]; present {
		t.Fatal("accepted success did not reset matching failure key")
	}
}

func TestM010RealCoverageEngineExcludesRepeatedRefusalThenResumes(t *testing.T) {
	ce, pol, views, _ := m019Scenario(t)
	views[0].Pod.HasGPU = true
	views[0].Pod.ModelID = "served-model"
	views[0].Pod.ServingEndpointReady = true
	views[0].HasEventEvidence = true
	views[0].Physics = model.NeutralPhysics()
	pol.EnabledActions[model.ActionKVReset] = true

	// Use the actual coverage producer to choose KV reset from the trusted KV vector.
	// This mirrors the existing M-19 producer fixture but drives the new explicit
	// nil-error refusal contract through the runner feedback store.
	views[0].Events = []model.SecurityEventInfo{{Name: "detector-kv", Type: model.AttackVectorKV, Source: "detector", TargetsPod: true}}
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW producer unavailable")
	}
	ce.Recon = profile
	now := time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC)
	hands := &m010FixedHands{result: actuator.Result{NoEffect: actuator.NoEffectRefused}}
	m := &Manager{Local: &inprocess.Services{Actuator: hands}, Intents: exposure.NewIntents(), Log: logr.Discard(), FailureNow: func() time.Time { return now }}
	ce.FailureExclusion = func(v *model.WorkloadView, a model.Action) (string, bool) {
		return m.Failures.exclusion(failureKey{pol.Owner(), v.Pod.Namespace, v.Pod.UID, a}, now)
	}
	viewMap := map[string]*model.WorkloadView{"ns/pod": views[0]}
	for tick := 0; tick < 2; tick++ {
		ds, err := ce.DecideChecked(views, pol)
		if err != nil || len(ds) != 1 || !ds[0].Selected || ds[0].Action != model.ActionKVReset {
			t.Fatalf("KV producer tick %d = %v %+v", tick, err, ds)
		}
		if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, viewMap); n != 0 || ds[0].DispatchOutcome != model.DispatchRefused {
			t.Fatalf("KV refusal tick %d = n=%d %+v", tick, n, ds[0])
		}
		now = now.Add(10 * time.Second)
	}
	after, err := ce.DecideChecked(views, pol)
	if err != nil || len(after) != 1 || !after[0].Selected || after[0].Action == model.ActionKVReset {
		t.Fatalf("cooldown did not exclude refused candidate: %v %+v", err, after)
	}
	key := failureKey{pol.Owner(), "ns", views[0].Pod.UID, model.ActionKVReset}
	retry := m.Failures.at[key].retry
	now = retry.Add(time.Nanosecond)
	resumed, err := ce.DecideChecked(views, pol)
	if err != nil || len(resumed) != 1 || !resumed[0].Selected || resumed[0].Action != model.ActionKVReset {
		t.Fatalf("expired cooldown did not restore candidate: %v %+v", err, resumed)
	}
}

func TestM010ClosedNoEffectDispositionRejectsContradictions(t *testing.T) {
	secret := "TOKEN=do-not-retain"
	for _, tc := range []struct {
		name string
		res  actuator.Result
		err  error
		want actuator.NoEffectDisposition
	}{
		{"explicit-refusal", actuator.Result{NoEffect: actuator.NoEffectRefused, Note: secret}, nil, actuator.NoEffectRefused},
		{"legacy-typed-refusal", actuator.Result{}, actuator.RefusedWithoutEffect(errors.New(secret)), actuator.NoEffectRefused},
		{"emitted-contradiction", actuator.Result{Emitted: true, NoEffect: actuator.NoEffectRefused}, nil, actuator.NoEffectUnknown},
		{"object-contradiction", actuator.Result{NoEffect: actuator.NoEffectRefused, ObjectsTouched: []string{"Pod/ns/p"}}, nil, actuator.NoEffectUnknown},
		{"partial-contradiction", actuator.Result{NoEffect: actuator.NoEffectRefused, MutationKind: "partial"}, nil, actuator.NoEffectUnknown},
		{"ordinary-error-contradiction", actuator.Result{NoEffect: actuator.NoEffectRefused}, errors.New(secret), actuator.NoEffectUnknown},
		{"timeout-contradiction", actuator.Result{NoEffect: actuator.NoEffectRefused}, context.DeadlineExceeded, actuator.NoEffectUnknown},
		{"ordinary-error", actuator.Result{}, errors.New(secret), actuator.NoEffectUnknown},
		{"unknown-value", actuator.Result{NoEffect: actuator.NoEffectDisposition("future")}, nil, actuator.NoEffectUnknown},
		{"satisfied", actuator.Result{NoEffect: actuator.NoEffectSatisfied}, nil, actuator.NoEffectSatisfied},
		{"reconciled-receipt", actuator.Result{NoEffect: actuator.NoEffectReconciled, ObjectsTouched: []string{"ConfigMap/operator/receipt"}, RollbackRef: "receipt"}, nil, actuator.NoEffectReconciled},
		{"declared", actuator.Result{NoEffect: actuator.NoEffectDeclared, MutationKind: "declared"}, nil, actuator.NoEffectDeclared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := noEffectDisposition(tc.res, tc.err); got != tc.want {
				t.Fatalf("disposition = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestM010ContradictoryRefusedEmissionStaysUnknownThroughRunnerEventAndAudit(t *testing.T) {
	secret := "TOKEN=must-not-escape"
	for _, tc := range []struct {
		name         string
		result       actuator.Result
		wantCount    int
		wantActuated bool
		wantOutcome  string
		wantReason   string
		wantEvent    string
	}{
		{
			name:        "refused-and-emitted-is-uncertain",
			result:      actuator.Result{Emitted: true, NoEffect: actuator.NoEffectRefused, Handler: "kv-reset", Note: secret},
			wantOutcome: model.DispatchError,
			wantReason:  "outcome-unknown",
			wantEvent:   "PhorvexActuationOutcomeUnknown",
		},
		{
			name:         "ordinary-emitted-result-remains-positive",
			result:       actuator.Result{Emitted: true, Handler: "kv-reset", Note: secret},
			wantCount:    1,
			wantActuated: true,
			wantOutcome:  model.DispatchEmitted,
			wantReason:   "emitted-unconfirmed",
			wantEvent:    "PhorvexActuationEmitted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hands := &m010FixedHands{result: tc.result}
			events := record.NewFakeRecorder(2)
			m := &Manager{Local: &inprocess.Services{Actuator: hands}, ActuationRecorder: events, Intents: exposure.NewIntents(), Log: logr.Discard()}
			ds := []model.Decision{{
				Namespace: "ns", Pod: "p1", Action: model.ActionKVReset, Selected: true, Feasible: true,
				Engine: "p1-coverage", CoverageValue: 1.25, CoveredWeight: 0.75,
			}}
			view := m010KVView("pod-uid")
			got := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, model.Policy{Tenant: "tenant"}, ds, map[string]*model.WorkloadView{"ns/p1": view})
			if got != tc.wantCount || ds[0].Actuated != tc.wantActuated || ds[0].DispatchOutcome != tc.wantOutcome || ds[0].DispatchReason != tc.wantReason {
				t.Fatalf("runner result: count=%d decision=%+v", got, ds[0])
			}
			if ds[0].Handler != "kv-reset" || len(m.Failures.at) != 0 || len(m.fallbackDecisions) != 0 {
				t.Fatalf("result evidence or feedback changed: decision=%+v failures=%+v fallback=%+v", ds[0], m.Failures.at, m.fallbackDecisions)
			}
			rec := audit.ToRecord(ds[0])
			if rec.DispatchOutcome != tc.wantOutcome || rec.DispatchReason != tc.wantReason || rec.CoverageBasis != "modeled-selection-opportunity" {
				t.Fatalf("audit record = %+v", rec)
			}
			msg := <-events.Events
			if !strings.Contains(msg, tc.wantEvent) || strings.Contains(msg, secret) {
				t.Fatalf("event = %q", msg)
			}
		})
	}
}

func TestM010SatisfiedReconciledAndDeclaredDoNotTeachFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		result      actuator.Result
		outcome     string
		reason      string
		wantObjects int
	}{
		{"satisfied", actuator.Result{NoEffect: actuator.NoEffectSatisfied}, model.DispatchSatisfied, "already-satisfied", 0},
		{"reconciled", actuator.Result{NoEffect: actuator.NoEffectReconciled, Handler: string(model.ActionAdapterRotate), MutationKind: "none", ObjectsTouched: []string{"ConfigMap/operator/receipt"}, RollbackRef: "operator/receipt@uid"}, model.DispatchReconciled, "reconciled-prior-operation", 1},
		{"declared", actuator.Result{NoEffect: actuator.NoEffectDeclared, Handler: string(model.ActionDisable), MutationKind: "declared"}, model.DispatchDeclared, "declared-without-implementation", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hands := &m010FixedHands{result: tc.result}
			m := &Manager{Local: &inprocess.Services{Actuator: hands}, Intents: exposure.NewIntents(), Log: logr.Discard()}
			ds := []model.Decision{{Namespace: "ns", Pod: "p1", Action: model.ActionKVReset, Selected: true, Feasible: true}}
			view := m010KVView("pod-uid")
			if got := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, model.Policy{Tenant: "tenant"}, ds, map[string]*model.WorkloadView{"ns/p1": view}); got != 0 {
				t.Fatalf("actuations = %d", got)
			}
			if ds[0].DispatchOutcome != tc.outcome || ds[0].DispatchReason != tc.reason || len(ds[0].ObjectsTouched) != tc.wantObjects || len(m.Failures.at) != 0 || len(m.fallbackDecisions) != 0 {
				t.Fatalf("decision=%+v failures=%+v fallback=%+v", ds[0], m.Failures.at, m.fallbackDecisions)
			}
		})
	}
}

func TestM010AuditAndOwnerDropUnreviewedDispatchText(t *testing.T) {
	secret := "TOKEN=private https://internal/tenant"
	rec := audit.ToRecord(model.Decision{Selected: true, DispatchOutcome: model.DispatchError, DispatchReason: secret})
	if rec.DispatchOutcome != model.DispatchError || rec.DispatchReason != "" {
		t.Fatalf("unsafe reason retained: %+v", rec)
	}
	owner := console.ToOwnerEvent(audit.Record{Selected: true, DispatchOutcome: model.DispatchError, DispatchReason: secret})
	raw, err := json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	if owner.DispatchReason != "" || strings.Contains(string(raw), secret) {
		t.Fatalf("unsafe owner history = %s", raw)
	}
	if model.SafeDispatchOutcome("future-confirmed") != "" || model.SafeDispatchReason(secret) != "" {
		t.Fatal("unrecognized public dispatch evidence was accepted")
	}
}
