package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	metricspkg "github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
)

func m012Counter(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	return metricValue(t, name, labels)
}

func m012MetricLabels(t *testing.T, name string) map[string]struct{} {
	t.Helper()
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name || len(family.Metric) == 0 {
			continue
		}
		labels := make(map[string]struct{})
		for _, pair := range family.Metric[0].Label {
			labels[pair.GetName()] = struct{}{}
		}
		return labels
	}
	return nil
}

func TestM012ActualHTTPAttemptOutcomesAndPreparationSuppression(t *testing.T) {
	tenant := "m012-http"
	pol := model.Policy{Tenant: tenant, EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	view := m010KVView("m012-http-uid")
	view.Pod.Name = "http-pod"
	views := map[string]*model.WorkloadView{"ns/http-pod": view}
	decision := func() []model.Decision {
		return []model.Decision{{Namespace: "ns", Pod: "http-pod", Action: model.ActionKVReset, Selected: true, Feasible: true}}
	}

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	hands := &m019HTTPTimeoutHands{client: &http.Client{Timeout: 10 * time.Millisecond}, url: server.URL}
	m := &Manager{Actuator: hands, Intents: exposure.NewIntents(), Log: logr.Discard()}
	labels := map[string]string{"tenant": tenant, "action": string(model.ActionKVReset), "outcome": string(metricspkg.AttemptDeadline)}
	failureLabels := map[string]string{"tenant": tenant, "action": string(model.ActionKVReset), "reason": string(metricspkg.AttemptDeadline)}
	beforeAttempts := m012Counter(t, "phorvex_actuation_attempts_total", labels)
	beforeFailures := m012Counter(t, "phorvex_actuation_failures_total", failureLabels)
	beforeAccepted := m012Counter(t, "phorvex_actuations_total", map[string]string{"tenant": tenant, "action": string(model.ActionKVReset)})
	got := decision()
	if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, got, views); n != 0 || hands.calls != 1 {
		t.Fatalf("timeout dispatch = n=%d calls=%d", n, hands.calls)
	}
	if m012Counter(t, "phorvex_actuation_attempts_total", labels) != beforeAttempts+1 ||
		m012Counter(t, "phorvex_actuation_failures_total", failureLabels) != beforeFailures+1 ||
		m012Counter(t, "phorvex_actuations_total", map[string]string{"tenant": tenant, "action": string(model.ActionKVReset)}) != beforeAccepted {
		t.Fatal("actual timeout did not produce exactly one bounded failure without accepted-emission credit")
	}

	prep := &m012PreparationHands{err: errors.New("route unavailable")}
	m.Actuator = prep
	suppressionLabels := map[string]string{"tenant": tenant, "action": string(model.ActionKVReset), "reason": string(metricspkg.SuppressEnsurePolicy)}
	beforeSuppressions := m012Counter(t, "phorvex_actuation_suppressions_total", suppressionLabels)
	beforeAllAttempts := m012Counter(t, "phorvex_actuation_attempts_total", labels)
	got = decision()
	if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, got, views); n != 0 || prep.calls != 0 {
		t.Fatalf("preparation refusal reached Actuate: n=%d calls=%d", n, prep.calls)
	}
	if m012Counter(t, "phorvex_actuation_suppressions_total", suppressionLabels) != beforeSuppressions+1 ||
		m012Counter(t, "phorvex_actuation_attempts_total", labels) != beforeAllAttempts {
		t.Fatal("selected preparation refusal was mixed into actual attempts")
	}
}

type m012PreparationHands struct {
	err   error
	calls int
}

type m012CapacityClient struct {
	client.Client
	failUpdate bool
}

func (c *m012CapacityClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		obj.SetUID(types.UID("m012-capacity-ledger"))
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *m012CapacityClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok && c.failUpdate {
		return errors.New("protected capacity ledger update unavailable")
	}
	before := obj.GetResourceVersion()
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	if obj.GetResourceVersion() == before {
		obj.SetResourceVersion(before + "-ack")
	}
	return nil
}

func m012CapacityFixture(t *testing.T, suffix string, limit int, failUpdate bool) (*Manager, *m010FixedHands, model.Policy, *policyEntry, map[string]*model.WorkloadView) {
	t.Helper()
	namespace := "m012-capacity-" + suffix
	scheme := m034Scheme(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: types.UID(namespace + "-uid")}}
	operatorNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m012-operator-" + suffix, UID: types.UID("operator-" + suffix)}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "target", UID: types.UID("target-" + suffix), ResourceVersion: "1"}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, operatorNS, pod).Build()
	c := &m012CapacityClient{Client: base, failUpdate: failUpdate}
	capacity, err := actuator.NewQuarantineCapacity(c, c, operatorNS.Name, limit)
	if err != nil {
		t.Fatal(err)
	}
	hands := &m010FixedHands{result: actuator.Result{
		Emitted: true, Handler: "quarantine", MutationKind: "reversible",
		ObjectsTouched: []string{"NetworkPolicy/" + namespace + "/target"},
	}}
	m := &Manager{Actuator: hands, QuarantineCapacity: capacity, Intents: exposure.NewIntents(), Log: logr.Discard()}
	pol := model.Policy{
		Tenant: namespace, Namespace: namespace, PolicyName: "policy", PolicyUID: "policy-" + suffix,
		EnabledActions: map[model.Action]bool{model.ActionQuarantine: true},
	}
	entry := &policyEntry{namespace: namespace}
	view := m010KVView(string(pod.UID))
	view.Pod.Namespace, view.Pod.Name = namespace, pod.Name
	return m, hands, pol, entry, map[string]*model.WorkloadView{namespace + "/" + pod.Name: view}
}

func TestM012QuarantineCapacityProvenanceSeparatesSuppressionFromAttempts(t *testing.T) {
	t.Run("reservation-refusal-is-suppression", func(t *testing.T) {
		m, hands, pol, entry, views := m012CapacityFixture(t, "refused", 0, false)
		ds := []model.Decision{{Namespace: entry.namespace, Pod: "target", Action: model.ActionQuarantine, Selected: true, Feasible: true}}
		suppressionLabels := map[string]string{"tenant": pol.Tenant, "action": string(model.ActionQuarantine), "reason": string(metricspkg.SuppressQuarantineCapacity)}
		attemptLabels := map[string]string{"tenant": pol.Tenant, "action": string(model.ActionQuarantine), "outcome": string(metricspkg.AttemptRefused)}
		suppressionsBefore := m012Counter(t, "phorvex_actuation_suppressions_total", suppressionLabels)
		attemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels)
		if n := actuateWithBoundary(t, m, context.Background(), entry, pol, ds, views); n != 0 || hands.calls != 0 {
			t.Fatalf("capacity refusal crossed backend boundary: n=%d calls=%d", n, hands.calls)
		}
		if ds[0].DispatchOutcome != model.DispatchNotAttempted || ds[0].DispatchReason != "quarantine-capacity-refused" ||
			m012Counter(t, "phorvex_actuation_suppressions_total", suppressionLabels) != suppressionsBefore+1 ||
			m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels) != attemptsBefore {
			t.Fatalf("capacity refusal accounting = %+v", ds[0])
		}
	})

	t.Run("accepted-backend-is-one-attempt", func(t *testing.T) {
		m, hands, pol, entry, views := m012CapacityFixture(t, "accepted", 1, false)
		ds := []model.Decision{{Namespace: entry.namespace, Pod: "target", Action: model.ActionQuarantine, Selected: true, Feasible: true}}
		attemptLabels := map[string]string{"tenant": pol.Tenant, "action": string(model.ActionQuarantine), "outcome": string(metricspkg.AttemptAccepted)}
		attemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels)
		if n := actuateWithBoundary(t, m, context.Background(), entry, pol, ds, views); n != 1 || hands.calls != 1 {
			t.Fatalf("accepted capacity dispatch = n=%d calls=%d decision=%+v", n, hands.calls, ds[0])
		}
		if m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels) != attemptsBefore+1 {
			t.Fatal("accepted capacity backend was not counted exactly once")
		}
	})

	t.Run("post-call-ledger-failure-retains-attempt-and-effects", func(t *testing.T) {
		m, hands, pol, entry, views := m012CapacityFixture(t, "finish-failed", 1, true)
		ds := []model.Decision{{Namespace: entry.namespace, Pod: "target", Action: model.ActionQuarantine, Selected: true, Feasible: true}}
		attemptLabels := map[string]string{"tenant": pol.Tenant, "action": string(model.ActionQuarantine), "outcome": string(metricspkg.AttemptError)}
		attemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels)
		if n := actuateWithBoundary(t, m, context.Background(), entry, pol, ds, views); n != 0 || hands.calls != 1 {
			t.Fatalf("post-call failure = n=%d calls=%d decision=%+v", n, hands.calls, ds[0])
		}
		if m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels) != attemptsBefore+1 ||
			ds[0].DispatchOutcome != model.DispatchError || len(ds[0].ObjectsTouched) != 1 ||
			ds[0].MutationKind != "reversible" {
			t.Fatalf("post-call effect/provenance lost: %+v", ds[0])
		}
	})
}

func (*m012PreparationHands) Name() string { return "native" }
func (h *m012PreparationHands) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return h.err
}
func (*m012PreparationHands) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (h *m012PreparationHands) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	h.calls++
	return actuator.Result{Emitted: true}, nil
}

func TestM012ForbiddenAndFallbackAttemptsAreCountedOnce(t *testing.T) {
	ce, pol, views, decisions := m019Scenario(t)
	pol.Tenant = "m012-fallback"
	primary := decisions[0].Action
	alternative, ok := ce.SelectAlternative(pol.Owner(), "ns/pod", primary)
	if !ok {
		t.Fatal("reserved alternative absent")
	}
	hands := &m019Hands{refusal: actuator.RefusedWithoutEffect(errors.New("precondition unavailable"))}
	m := &Manager{Actuator: hands, Optimizer: ce, Intents: exposure.NewIntents(), Log: logr.Discard()}
	primaryLabels := map[string]string{"tenant": pol.Tenant, "action": string(primary), "outcome": string(metricspkg.AttemptRefused)}
	fallbackLabels := map[string]string{"tenant": pol.Tenant, "action": string(alternative.Action), "outcome": string(metricspkg.AttemptAccepted)}
	primaryFailureLabels := map[string]string{"tenant": pol.Tenant, "action": string(primary), "reason": string(metricspkg.AttemptRefused)}
	primaryBefore := m012Counter(t, "phorvex_actuation_attempts_total", primaryLabels)
	fallbackBefore := m012Counter(t, "phorvex_actuation_attempts_total", fallbackLabels)
	primaryFailuresBefore := m012Counter(t, "phorvex_actuation_failures_total", primaryFailureLabels)
	if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, decisions, map[string]*model.WorkloadView{"ns/pod": views[0]}); n != 1 {
		t.Fatalf("fallback actuations = %d", n)
	}
	if len(hands.calls) != 2 || m012Counter(t, "phorvex_actuation_attempts_total", primaryLabels) != primaryBefore+1 ||
		m012Counter(t, "phorvex_actuation_attempts_total", fallbackLabels) != fallbackBefore+1 {
		t.Fatalf("primary/fallback accounting drift: calls=%v", hands.calls)
	}
	if got := m012Counter(t, "phorvex_actuation_failures_total", primaryFailureLabels); got != primaryFailuresBefore+1 {
		t.Fatalf("explicit refusal failure count = %v, want %v", got, primaryFailuresBefore+1)
	}

	// An injected typed API Forbidden unit control is a failed attempt, not an explicit
	// proof of no effect and therefore cannot license the reserved alternative. The
	// isolated API-server authorization control lives in m012_actuation_metrics_apiserver_test.go.
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "pod", errors.New("denied"))
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	controller := true
	replicas := int32(1)
	rc := &corev1.ReplicationController{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rc", UID: types.UID("rc-uid"), ResourceVersion: "1"},
		Spec:       corev1.ReplicationControllerSpec{Replicas: &replicas, Selector: map[string]string{"app": "demo"}},
		Status:     corev1.ReplicationControllerStatus{Replicas: 1},
	}
	apiPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "api-pod", UID: types.UID("api-pod-uid"), ResourceVersion: "1",
		Labels: map[string]string{"app": "demo"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "ReplicationController", Name: rc.Name, UID: rc.UID, Controller: &controller,
		}},
	}}
	deleteCalls := 0
	apiClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rc, apiPod).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			deleteCalls++
			return forbidden
		},
	}).Build()
	apiNative := actuator.NewNativeActuator(apiClient)
	apiNative.SetBoundaryReader(apiClient)
	apiManager := &Manager{Actuator: apiNative, Intents: exposure.NewIntents(), Log: logr.Discard()}
	apiPolicy := model.Policy{Tenant: "m012-api-forbidden", EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	apiView := m010KVView(string(apiPod.UID))
	apiView.Pod.Name = apiPod.Name
	apiDecision := []model.Decision{{Namespace: "ns", Pod: apiPod.Name, Action: model.ActionRotate, Selected: true, Feasible: true}}
	apiLabels := map[string]string{"tenant": apiPolicy.Tenant, "action": string(model.ActionRotate), "outcome": string(metricspkg.AttemptError)}
	apiFailureLabels := map[string]string{"tenant": apiPolicy.Tenant, "action": string(model.ActionRotate), "reason": string(metricspkg.AttemptError)}
	apiAttemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", apiLabels)
	apiFailuresBefore := m012Counter(t, "phorvex_actuation_failures_total", apiFailureLabels)
	if n := actuateWithBoundary(t, apiManager, context.Background(), m010Entry(), apiPolicy, apiDecision, map[string]*model.WorkloadView{"ns/" + apiPod.Name: apiView}); n != 0 || deleteCalls != 1 {
		t.Fatalf("forbidden dispatch = n=%d deletes=%d", n, deleteCalls)
	}
	if m012Counter(t, "phorvex_actuation_attempts_total", apiLabels) != apiAttemptsBefore+1 ||
		m012Counter(t, "phorvex_actuation_failures_total", apiFailureLabels) != apiFailuresBefore+1 {
		t.Fatal("API Forbidden did not produce exactly one attempted failure")
	}
}

func TestM012ActualNativeStaleUIDRefusalHasNoAcceptedCredit(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p1", UID: types.UID("current-uid"), ResourceVersion: "1"},
		Status:     corev1.PodStatus{PodIP: "127.0.0.1"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	m := &Manager{Actuator: native, Intents: exposure.NewIntents(), Log: logr.Discard()}
	tenant := "m012-native-stale"
	pol := model.Policy{Tenant: tenant, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	view := m010KVView("stale-uid")
	decisions := []model.Decision{{Namespace: "ns", Pod: "p1", Action: model.ActionRotate, Selected: true, Feasible: true}}
	attemptLabels := map[string]string{"tenant": tenant, "action": string(model.ActionRotate), "outcome": string(metricspkg.AttemptRefused)}
	failureLabels := map[string]string{"tenant": tenant, "action": string(model.ActionRotate), "reason": string(metricspkg.AttemptRefused)}
	acceptedLabels := map[string]string{"tenant": tenant, "action": string(model.ActionRotate)}
	attemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels)
	failuresBefore := m012Counter(t, "phorvex_actuation_failures_total", failureLabels)
	acceptedBefore := m012Counter(t, "phorvex_actuations_total", acceptedLabels)
	if n := actuateWithBoundary(t, m, context.Background(), m010Entry(), pol, decisions, map[string]*model.WorkloadView{"ns/p1": view}); n != 0 {
		t.Fatalf("stale identity actuations = %d", n)
	}
	var current corev1.Pod
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "p1"}, &current); err != nil {
		t.Fatalf("current Pod was mutated/deleted: %v", err)
	}
	if current.UID != pod.UID || m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels) != attemptsBefore+1 ||
		m012Counter(t, "phorvex_actuation_failures_total", failureLabels) != failuresBefore+1 ||
		m012Counter(t, "phorvex_actuations_total", acceptedLabels) != acceptedBefore {
		t.Fatalf("stale identity metrics/object drift: current=%s decision=%+v", current.UID, decisions[0])
	}
}

func TestM012ClosedAttemptOutcomeVocabularyAtRunnerBoundary(t *testing.T) {
	cases := []struct {
		name    string
		result  actuator.Result
		err     error
		outcome metricspkg.ActuationAttemptOutcome
		failure bool
	}{
		{name: "accepted", result: actuator.Result{Emitted: true}, outcome: metricspkg.AttemptAccepted},
		{name: "error", err: errors.New("backend unavailable"), outcome: metricspkg.AttemptError, failure: true},
		{name: "deadline", err: context.DeadlineExceeded, outcome: metricspkg.AttemptDeadline, failure: true},
		{name: "unknown", result: actuator.Result{}, outcome: metricspkg.AttemptUnknown, failure: true},
		{name: "contradictory", result: actuator.Result{Emitted: true, NoEffect: actuator.NoEffectRefused}, outcome: metricspkg.AttemptUnknown, failure: true},
		{name: "refused", result: actuator.Result{NoEffect: actuator.NoEffectRefused}, outcome: metricspkg.AttemptRefused, failure: true},
		{name: "satisfied", result: actuator.Result{NoEffect: actuator.NoEffectSatisfied}, outcome: metricspkg.AttemptSatisfied},
		{name: "reconciled", result: actuator.Result{NoEffect: actuator.NoEffectReconciled, RollbackRef: "protected-receipt"}, outcome: metricspkg.AttemptReconciled},
		{name: "declared", result: actuator.Result{NoEffect: actuator.NoEffectDeclared, MutationKind: "declared"}, outcome: metricspkg.AttemptDeclared},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := "m012-outcome-" + tc.name
			action := model.ActionKVReset
			hands := &m010FixedHands{result: tc.result, err: tc.err}
			m := &Manager{Actuator: hands, Intents: exposure.NewIntents(), Log: logr.Discard()}
			pol := model.Policy{Tenant: tenant, EnabledActions: map[model.Action]bool{action: true}}
			view := m010KVView("outcome-uid")
			ds := []model.Decision{{Namespace: "ns", Pod: "p1", Action: action, Selected: true, Feasible: true}}
			attemptLabels := map[string]string{"tenant": tenant, "action": string(action), "outcome": string(tc.outcome)}
			failureLabels := map[string]string{"tenant": tenant, "action": string(action), "reason": string(tc.outcome)}
			attemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels)
			failuresBefore := m012Counter(t, "phorvex_actuation_failures_total", failureLabels)
			actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{"ns/p1": view})
			if hands.calls != 1 || m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels) != attemptsBefore+1 {
				t.Fatalf("attempt accounting = calls=%d decision=%+v", hands.calls, ds[0])
			}
			wantFailures := failuresBefore
			if tc.failure {
				wantFailures++
			}
			if got := m012Counter(t, "phorvex_actuation_failures_total", failureLabels); got != wantFailures {
				t.Fatalf("failure counter = %v, want %v", got, wantFailures)
			}
		})
	}
}

func TestM012SafetySuppressionAndSelectedNoopStayOutsideFailures(t *testing.T) {
	tenant := "m012-safety"
	hands := &m010FixedHands{result: actuator.Result{Emitted: true}}
	m := &Manager{Actuator: hands, Intents: exposure.NewIntents(), Log: logr.Discard()}
	pol := model.Policy{Tenant: tenant}
	view := m010KVView("safety-uid")
	ds := []model.Decision{{Namespace: "ns", Pod: "p1", Action: model.ActionNoop, Selected: true, Feasible: true}}
	suppressionLabels := map[string]string{"tenant": tenant, "action": string(model.ActionNoop), "reason": string(metricspkg.SuppressInviolability)}
	attemptLabels := map[string]string{"tenant": tenant, "action": string(model.ActionNoop), "outcome": string(metricspkg.AttemptAccepted)}
	suppressionsBefore := m012Counter(t, "phorvex_actuation_suppressions_total", suppressionLabels)
	attemptsBefore := m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels)
	actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{"ns/p1": view})
	if hands.calls != 0 || m012Counter(t, "phorvex_actuation_suppressions_total", suppressionLabels) != suppressionsBefore+1 ||
		m012Counter(t, "phorvex_actuation_attempts_total", attemptLabels) != attemptsBefore {
		t.Fatalf("selected noop entered backend attempts: calls=%d decision=%+v", hands.calls, ds[0])
	}
}

func TestM012CircuitProjectionExpirySuccessOwnershipAndRegistration(t *testing.T) {
	now := time.Date(2026, 9, 17, 3, 0, 0, 0, time.UTC)
	m := &Manager{policies: map[string]*policyEntry{}, emits: map[string]*emissionHistory{}}
	first := m140Policy("first", "shared-display", "owner-a")
	second := m140Policy("second", "shared-display", "owner-b")
	if err := m.Upsert(first); err != nil {
		t.Fatal(err)
	}
	if err := m.Upsert(second); err != nil {
		t.Fatal(err)
	}
	keyA := failureKey{ownerOfUID("owner-a"), "ns", "pod-a", model.ActionKVReset}
	keyB := failureKey{ownerOfUID("owner-b"), "ns", "pod-b", model.ActionKVReset}
	for _, key := range []failureKey{keyA, keyB} {
		m.Failures.observe(key, now)
		m.Failures.observe(key, now.Add(time.Second))
	}
	rows := m.currentActuationCircuits(now.Add(2 * time.Second))
	if len(rows) != 1 || rows[0].Tenant != "shared-display" || rows[0].Action != string(model.ActionKVReset) || rows[0].Count != 2 {
		t.Fatalf("shared display aggregation = %+v", rows)
	}

	scrapeNow := now.Add(2 * time.Second)
	releaseOld := metricspkg.BindActuationCircuitSource(func(time.Time) []metricspkg.ActuationCircuit {
		return m.currentActuationCircuits(scrapeNow)
	})
	t.Cleanup(releaseOld)
	labels := map[string]string{"tenant": "shared-display", "action": string(model.ActionKVReset)}
	if got := metricValue(t, "phorvex_actuation_circuit_open", labels); got != 2 {
		t.Fatalf("open gauge = %v", got)
	}

	// A newer binding survives release of the stale source and keeps its own state.
	replacement := &Manager{policies: map[string]*policyEntry{}}
	if err := replacement.Upsert(m140Policy("replacement", "replacement-display", "owner-c")); err != nil {
		t.Fatal(err)
	}
	keyC := failureKey{ownerOfUID("owner-c"), "ns", "pod-c", model.ActionRotate}
	replacement.Failures.observe(keyC, now)
	replacement.Failures.observe(keyC, now.Add(time.Second))
	releaseNew := metricspkg.BindActuationCircuitSource(func(time.Time) []metricspkg.ActuationCircuit {
		return replacement.currentActuationCircuits(scrapeNow)
	})
	t.Cleanup(releaseNew)
	releaseOld()
	if got := metricValue(t, "phorvex_actuation_circuit_open", map[string]string{"tenant": "replacement-display", "action": string(model.ActionRotate)}); got != 1 {
		t.Fatalf("stale release cleared current source: %v", got)
	}

	// Scrape-time expiry removes the projection without a decision tick.
	scrapeNow = now.Add(time.Minute)
	if got := metricValue(t, "phorvex_actuation_circuit_open", map[string]string{"tenant": "replacement-display", "action": string(model.ActionRotate)}); got != 0 {
		t.Fatalf("expired circuit remained published: %v", got)
	}
	// A successful matching dispatch clears the underlying record immediately.
	scrapeNow = now.Add(2 * time.Second)
	replacement.Failures.reset(keyC)
	if got := metricValue(t, "phorvex_actuation_circuit_open", map[string]string{"tenant": "replacement-display", "action": string(model.ActionRotate)}); got != 0 {
		t.Fatalf("successful reset remained published: %v", got)
	}

	// A replacement owner cannot inherit or publish its predecessor's open target.
	replacement.Failures.observe(keyC, now)
	replacement.Failures.observe(keyC, now.Add(time.Second))
	if err := replacement.Upsert(m140Policy("replacement", "replacement-display", "owner-d")); err != nil {
		t.Fatal(err)
	}
	if got := metricValue(t, "phorvex_actuation_circuit_open", map[string]string{"tenant": "replacement-display", "action": string(model.ActionRotate)}); got != 0 {
		t.Fatalf("replacement inherited predecessor circuit: %v", got)
	}
	replacement.DrainLifecycle()

	// A new target UID has independent history and owner removal withdraws its display
	// label before the serialized lifecycle drain completes.
	newUID := failureKey{ownerOfUID("owner-d"), "ns", "pod-c-new", model.ActionRotate}
	replacement.Failures.observe(newUID, now)
	replacement.Failures.observe(newUID, now.Add(time.Second))
	replacement.Remove(types.NamespacedName{Namespace: "ns", Name: "replacement"})
	if got := metricValue(t, "phorvex_actuation_circuit_open", map[string]string{"tenant": "replacement-display", "action": string(model.ActionRotate)}); got != 0 {
		t.Fatalf("retired owner remained published: %v", got)
	}
	replacement.DrainLifecycle()
	if rows := replacement.Failures.openByOwner(scrapeNow); len(rows) != 0 {
		t.Fatalf("retired owner retained cooldown state: %+v", rows)
	}
	releaseNew()
	if got := metricValue(t, "phorvex_actuation_circuit_open", map[string]string{"tenant": "replacement-display", "action": string(model.ActionRotate)}); got != 0 {
		t.Fatalf("stopped manager source retained output: %v", got)
	}
}

func TestM012CircuitConcurrentObservationScrapeAndRetirement(t *testing.T) {
	now := time.Now()
	m := &Manager{policies: map[string]*policyEntry{}, emits: map[string]*emissionHistory{}}
	if err := m.Upsert(m140Policy("policy", "m012-race", "race-owner")); err != nil {
		t.Fatal(err)
	}
	key := failureKey{ownerOfUID("race-owner"), "ns", "race-pod", model.ActionKVReset}
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			m.Failures.observe(key, now.Add(time.Duration(i)*time.Millisecond))
			if i%3 == 0 {
				m.Failures.reset(key)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = m.currentActuationCircuits(now.Add(time.Duration(i) * time.Millisecond))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = m.Failures.exclusion(key, now.Add(time.Duration(i)*time.Millisecond))
		}
	}()
	go func() {
		defer wg.Done()
		m.Remove(types.NamespacedName{Namespace: "ns", Name: "policy"})
	}()
	wg.Wait()
	m.DrainLifecycle()
	if len(m.currentActuationCircuits(now)) != 0 {
		t.Fatal("retirement left a circuit projection")
	}
}

func TestM012AcceptedRunnerAttemptClearsCurrentCircuit(t *testing.T) {
	now := time.Date(2026, 9, 17, 4, 0, 0, 0, time.UTC)
	hands := &m010FixedHands{result: actuator.Result{NoEffect: actuator.NoEffectRefused}}
	m := &Manager{
		Actuator: hands, Intents: exposure.NewIntents(), Log: logr.Discard(),
		FailureNow: func() time.Time { return now },
		policies:   map[string]*policyEntry{}, emits: map[string]*emissionHistory{},
	}
	if err := m.Upsert(m140Policy("policy", "m012-reset", "reset-owner")); err != nil {
		t.Fatal(err)
	}
	pol := model.Policy{
		Tenant: "m012-reset", PolicyUID: "reset-owner",
		EnabledActions: map[model.Action]bool{model.ActionKVReset: true},
	}
	m.tickEpochs = map[string]uint64{pol.Owner(): m.ownerEpoch(pol.Owner())}
	view := m010KVView("reset-pod-uid")
	dispatch := func() []model.Decision {
		return []model.Decision{{Namespace: "ns", Pod: "p1", Action: model.ActionKVReset, Selected: true, Feasible: true}}
	}
	for i := 0; i < 2; i++ {
		ds := dispatch()
		actuateWithBoundary(t, m, context.Background(), m010Entry(), pol, ds, map[string]*model.WorkloadView{"ns/p1": view})
		now = now.Add(time.Second)
	}
	if rows := m.currentActuationCircuits(now); len(rows) != 1 || rows[0].Count != 1 {
		t.Fatalf("two refused attempts did not open circuit: %+v", rows)
	}
	hands.result = actuator.Result{Emitted: true}
	ds := dispatch()
	if n := actuateWithBoundary(t, m, context.Background(), m010Entry(), pol, ds, map[string]*model.WorkloadView{"ns/p1": view}); n != 1 {
		t.Fatalf("accepted attempts = %d", n)
	}
	if rows := m.currentActuationCircuits(now); len(rows) != 0 {
		t.Fatalf("accepted attempt left circuit open: %+v", rows)
	}
}

func TestM012MetricLabelsStayBounded(t *testing.T) {
	metricspkg.RecordActuationAttempt("m012-labels", string(model.ActionKVReset), metricspkg.AttemptError)
	metricspkg.RecordActuationSuppression("m012-labels", string(model.ActionKVReset), metricspkg.SuppressKillSwitch)
	release := metricspkg.BindActuationCircuitSource(func(time.Time) []metricspkg.ActuationCircuit {
		return []metricspkg.ActuationCircuit{{Tenant: "m012-labels", Action: string(model.ActionKVReset), Count: 1}}
	})
	defer release()
	for name, want := range map[string]map[string]struct{}{
		"phorvex_actuation_attempts_total":     {"tenant": {}, "action": {}, "outcome": {}},
		"phorvex_actuation_failures_total":     {"tenant": {}, "action": {}, "reason": {}},
		"phorvex_actuation_suppressions_total": {"tenant": {}, "action": {}, "reason": {}},
		"phorvex_actuation_circuit_open":       {"tenant": {}, "action": {}},
	} {
		got := m012MetricLabels(t, name)
		if len(got) != len(want) {
			t.Fatalf("%s labels = %v", name, got)
		}
		for label := range want {
			if _, ok := got[label]; !ok {
				t.Fatalf("%s missing label %q: %v", name, label, got)
			}
		}
	}
}
