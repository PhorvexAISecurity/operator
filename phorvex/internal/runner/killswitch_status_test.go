package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
)

// killswitch_status_test.go — PHVX-17 / PHORVEXSEC-109 / M-127.
//
// PHVX-17 made the false value explicit on the wire. M-127 keeps that compatibility
// while carrying the observation used by the latest actuation boundary into the
// audit and status condition.

// TestKillSwitchFalseIsSerialised is the regression. A safety-control readout must state the safe
// value explicitly; omitting it is not the same as reporting it.
func TestKillSwitchFalseIsSerialised(t *testing.T) {
	b, err := json.Marshal(v1.PhorvexPolicyStatus{KillSwitchEngaged: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"killSwitchEngaged":false`) {
		t.Fatalf("a disengaged kill-switch did not serialise. With omitempty the field vanishes and "+
			"an operator cannot distinguish a running defence from a status that was never "+
			"reconciled. Got: %s", b)
	}
}

func TestKillSwitchTrueStillSerialises(t *testing.T) {
	b, _ := json.Marshal(v1.PhorvexPolicyStatus{KillSwitchEngaged: true})
	if !strings.Contains(string(b), `"killSwitchEngaged":true`) {
		t.Fatalf("engaged kill-switch missing from the status: %s", b)
	}
}

func TestKillSwitchStatusUsesTheBoundaryObservationCause(t *testing.T) {
	tests := []KillSwitchObservation{
		{Engaged: true, Cause: KillSwitchStaticFlag},
		{Engaged: true, Cause: KillSwitchSentinelEngaged},
		{Engaged: true, Cause: KillSwitchMissingNamespace},
		{Engaged: true, Cause: KillSwitchReadError},
		{Engaged: true, Cause: KillSwitchMalformedValue},
		{Cause: KillSwitchSentinelDisengaged},
		{Cause: KillSwitchSentinelAbsent},
		{Cause: KillSwitchSentinelKeyAbsent},
		{Cause: KillSwitchStaticOnly},
	}
	for _, observation := range tests {
		t.Run(string(observation.Cause), func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := v1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			policy := &v1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "status-cause", Name: "policy"}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.PhorvexPolicy{}).WithObjects(policy).Build()
			m := &Manager{Client: c, Log: logr.Discard()}
			e := &policyEntry{key: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}}
			m.updateStatusObserved(context.Background(), e, 1, 1, 0, observation, time.Now())

			var got v1.PhorvexPolicy
			if err := c.Get(context.Background(), e.key, &got); err != nil {
				t.Fatal(err)
			}
			condition := meta.FindStatusCondition(got.Status.Conditions, "KillSwitch")
			wantStatus := metav1.ConditionFalse
			if observation.Engaged {
				wantStatus = metav1.ConditionTrue
			}
			if got.Status.KillSwitchEngaged != observation.Engaged || condition == nil ||
				condition.Status != wantStatus || condition.Reason != string(observation.Cause) ||
				condition.Message != observation.message() {
				t.Fatalf("status does not describe observation %+v: %+v", observation, got.Status)
			}
		})
	}
}

type killSwitchOptimizer struct{}

func (*killSwitchOptimizer) Name() string { return "kill-switch-integration" }
func (*killSwitchOptimizer) Decide(views []*model.WorkloadView, _ model.Policy) []model.Decision {
	if len(views) == 0 {
		return nil
	}
	p := views[0].Pod
	return []model.Decision{{
		Namespace:     p.Namespace,
		Pod:           p.Name,
		Action:        model.ActionRotate,
		Selected:      true,
		Feasible:      true,
		CoverageValue: 0.5,
		Trace: &model.DecisionTraceV2{
			DispatchOutcome: model.DispatchNotAttempted,
			DispatchReason:  "pending-dispatch",
		},
	}}
}

func metricValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, sample := range family.Metric {
			got := map[string]string{}
			for _, pair := range sample.Label {
				got[pair.GetName()] = pair.GetValue()
			}
			matches := true
			for k, want := range labels {
				if got[k] != want {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			if sample.Counter != nil {
				return sample.Counter.GetValue()
			}
			if sample.Gauge != nil {
				return sample.Gauge.GetValue()
			}
		}
	}
	return 0
}

// TestKillSwitchEngageDisengageSuppressesAndResumesActuation exercises the actual sentinel read,
// the processTenant actuation gate, Prometheus counters, and the CR status in one path. A JSON-only
// test cannot prove the safety control stops writes or that turning it off resumes them.
func TestKillSwitchEngageDisengageSuppressesAndResumesActuation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	const (
		namespace  = "ks-integration"
		policyName = "active-policy"
		tenant     = "ks-integration-tenant"
		podName    = "api-0"
		operatorNS = "phorvex-system"
	)
	spec := v1.PhorvexPolicySpec{
		Tenant: tenant,
		Mode:   "active",
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{
			"app": "api",
		}},
	}
	policy := &v1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: policyName},
		Spec:       spec,
	}
	sentinel := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: operatorNS, Name: DefaultKillSwitchName},
		Data:       map[string]string{"engaged": "true"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1.PhorvexPolicy{}).
		WithObjects(policy, sentinel,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: podName, UID: types.UID("uid-1")}},
		).Build()
	fa := &m127BoundaryActuator{name: "fake"}
	notifications := record.NewFakeRecorder(4)
	var auditSink bytes.Buffer
	m := &Manager{
		BrainImage: "record-image", GitSHA: "record-sha",
		Client:            c,
		BoundaryReader:    c,
		Clock:             exposure.NewClock(),
		Optimizer:         &killSwitchOptimizer{},
		Audit:             audit.New(logr.Discard(), &auditSink),
		Actuator:          fa,
		ActuationRecorder: notifications,
		KillSwitch:        &KillSwitch{Client: c, Namespace: operatorNS},
		Log:               logr.Discard(),
		policies:          map[string]*policyEntry{},
	}
	e := &policyEntry{
		key:       types.NamespacedName{Namespace: namespace, Name: policyName},
		tenant:    tenant,
		namespace: namespace,
		spec:      spec,
		selector:  labels.SelectorFromSet(map[string]string{"app": "api"}),
	}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	pod := model.Pod{
		Namespace: namespace, Name: podName, UID: "uid-1", Labels: map[string]string{"app": "api"},
		StartedAt: now.Add(-time.Hour), Ready: true, DesiredReplicas: 2, ReadyReplicas: 2,
	}
	snap := &ingest.Snapshot{
		Pods:            []model.Pod{pod},
		PodByKey:        map[string]*model.Pod{namespace + "/" + podName: &pod},
		Graph:           graph.Build(graph.Input{}),
		EventByPod:      map[string][]model.SecurityEventInfo{},
		NamespaceDryRun: map[string]model.ActuationBrakeObservation{},
		Now:             now,
	}
	decisionLabels := map[string]string{
		"tenant": tenant, "action": string(model.ActionRotate), "mode": "active", "selected": "true",
	}
	actuationLabels := map[string]string{"tenant": tenant, "action": string(model.ActionRotate)}
	decisionsBefore := metricValue(t, "phorvex_decisions_total", decisionLabels)
	actuationsBefore := metricValue(t, "phorvex_actuations_total", actuationLabels)

	observation := m.KillSwitch.Observe(context.Background())
	if !observation.Engaged || observation.Cause != KillSwitchSentinelEngaged {
		t.Fatalf("initial engaged sentinel was not observed: %+v", observation)
	}
	_, physicsByKey := platform.Derive(snap)
	m.processTenantWithPhysicsObserved(context.Background(), snap, e, &observation, physicsByKey)
	if !observation.Engaged || observation.Cause != KillSwitchSentinelEngaged {
		t.Fatalf("engaged sentinel was not retained for the tick: %+v", observation)
	}
	// The normal runner attaches record-time metadata even without decision tracing.
	var recorded audit.Record
	if err := json.NewDecoder(&auditSink).Decode(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Claim == nil || recorded.Claim.BrainImage != "record-image" || recorded.Claim.GitSHA != "record-sha" || !recorded.Claim.DetectorSetKnown {
		t.Fatalf("missing runner claim: %+v", recorded.Claim)
	}
	if recorded.Representation == nil || recorded.Representation.CoverageShare.Share.Present || recorded.Representation.Snapshot.Scope.Version != "uid-1" {
		t.Fatalf("missing or dishonest runner representation: %+v", recorded.Representation)
	}
	if recorded.Actuated {
		t.Fatal("claim metadata bypassed kill-switch")
	}
	if recorded.Measurements == nil || !recorded.Measurements.KillSwitch.Present || !recorded.Measurements.KillSwitch.Value {
		t.Fatalf("engaged kill-switch measurement missing: %+v", recorded.Measurements)
	}
	if recorded.KillSwitchCause != string(KillSwitchSentinelEngaged) {
		t.Fatalf("engaged audit cause = %q", recorded.KillSwitchCause)
	}

	if fa.actuateCalls != 0 {
		t.Fatalf("kill-switch engaged: actuator called %d times, want 0", fa.actuateCalls)
	}
	if got := metricValue(t, "phorvex_decisions_total", decisionLabels); got != decisionsBefore+1 {
		t.Fatalf("engaged decision counter = %v, want %v (decisions must continue)", got, decisionsBefore+1)
	}
	if got := metricValue(t, "phorvex_actuations_total", actuationLabels); got != actuationsBefore {
		t.Fatalf("engaged actuation counter changed from %v to %v", actuationsBefore, got)
	}
	var gotPolicy v1.PhorvexPolicy
	if err := c.Get(context.Background(), e.key, &gotPolicy); err != nil {
		t.Fatal(err)
	}
	ks := meta.FindStatusCondition(gotPolicy.Status.Conditions, "KillSwitch")
	if !gotPolicy.Status.KillSwitchEngaged || gotPolicy.Status.Actuated ||
		ks == nil || ks.Status != metav1.ConditionTrue || ks.Reason != string(KillSwitchSentinelEngaged) {
		t.Fatalf("engaged status did not match the actuation gate: %+v", gotPolicy.Status)
	}

	if len(notifications.Events) != 0 {
		t.Fatal("selected but suppressed decision emitted notification")
	}
	var gotSentinel corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(sentinel), &gotSentinel); err != nil {
		t.Fatal(err)
	}
	gotSentinel.Data["engaged"] = "false"
	if err := c.Update(context.Background(), &gotSentinel); err != nil {
		t.Fatal(err)
	}
	fa.ensure = func(ctx context.Context) error {
		var current corev1.ConfigMap
		if err := c.Get(ctx, client.ObjectKeyFromObject(sentinel), &current); err != nil {
			return err
		}
		current.Data["engaged"] = "true"
		return c.Update(ctx, &current)
	}
	observation = m.KillSwitch.Observe(context.Background())
	if observation.Engaged || observation.Cause != KillSwitchSentinelDisengaged {
		t.Fatal("disengaged sentinel still reported engaged")
	}
	snap.Now = now.Add(time.Second)
	_, physicsByKey = platform.Derive(snap)
	m.processTenantWithPhysicsObserved(context.Background(), snap, e, &observation, physicsByKey)
	if !observation.Engaged || observation.Cause != KillSwitchSentinelEngaged {
		t.Fatalf("late sentinel engagement was not retained for the tick: %+v audit=%s", observation, auditSink.String())
	}
	if err := json.NewDecoder(&auditSink).Decode(&recorded); err != nil {
		t.Fatal(err)
	}
	if !recorded.KillSwitch || recorded.KillSwitchCause != string(KillSwitchSentinelEngaged) ||
		recorded.Measurements == nil || !recorded.Measurements.KillSwitch.Present || !recorded.Measurements.KillSwitch.Value {
		t.Fatalf("late refusal audit did not match the dispatch gate: %+v", recorded)
	}
	if fa.actuateCalls != 0 || len(notifications.Events) != 0 {
		t.Fatalf("late engagement dispatched: calls=%d events=%d", fa.actuateCalls, len(notifications.Events))
	}
	if got := metricValue(t, "phorvex_decisions_total", decisionLabels); got != decisionsBefore+2 {
		t.Fatalf("decision counter after late refusal = %v, want %v", got, decisionsBefore+2)
	}
	if err := c.Get(context.Background(), e.key, &gotPolicy); err != nil {
		t.Fatal(err)
	}
	ks = meta.FindStatusCondition(gotPolicy.Status.Conditions, "KillSwitch")
	if !gotPolicy.Status.KillSwitchEngaged || gotPolicy.Status.Actuated ||
		gotPolicy.Status.DecisionsTotal != 2 || ks == nil || ks.Reason != string(KillSwitchSentinelEngaged) {
		t.Fatalf("late refusal status did not match the dispatch gate: %+v", gotPolicy.Status)
	}

	if err := c.Get(context.Background(), client.ObjectKeyFromObject(sentinel), &gotSentinel); err != nil {
		t.Fatal(err)
	}
	gotSentinel.Data["engaged"] = "false"
	if err := c.Update(context.Background(), &gotSentinel); err != nil {
		t.Fatal(err)
	}
	fa.ensure = nil
	observation = m.KillSwitch.Observe(context.Background())
	if observation.Engaged || observation.Cause != KillSwitchSentinelDisengaged {
		t.Fatalf("disengaged sentinel did not resume: %+v", observation)
	}
	snap.Now = now.Add(2 * time.Second)
	_, physicsByKey = platform.Derive(snap)
	m.processTenantWithPhysicsObserved(context.Background(), snap, e, &observation, physicsByKey)
	if err := json.NewDecoder(&auditSink).Decode(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Measurements == nil || !recorded.Measurements.KillSwitch.Present || recorded.Measurements.KillSwitch.Value {
		t.Fatalf("disengaged kill-switch false missing: %+v", recorded.Measurements)
	}
	if recorded.KillSwitchCause != "" {
		t.Fatalf("disengaged decision unexpectedly carried refusal cause %q", recorded.KillSwitchCause)
	}
	if len(notifications.Events) != 1 {
		t.Fatalf("active attempt events = %d", len(notifications.Events))
	}
	if fa.actuateCalls != 1 {
		t.Fatalf("kill-switch disengaged: actuator called %d times, want 1", fa.actuateCalls)
	}
	if got := metricValue(t, "phorvex_decisions_total", decisionLabels); got != decisionsBefore+3 {
		t.Fatalf("decision counter after resume = %v, want %v", got, decisionsBefore+3)
	}
	if got := metricValue(t, "phorvex_actuations_total", actuationLabels); got != actuationsBefore+1 {
		t.Fatalf("actuation counter after resume = %v, want %v", got, actuationsBefore+1)
	}
	if err := c.Get(context.Background(), e.key, &gotPolicy); err != nil {
		t.Fatal(err)
	}
	ks = meta.FindStatusCondition(gotPolicy.Status.Conditions, "KillSwitch")
	if gotPolicy.Status.KillSwitchEngaged || !gotPolicy.Status.Actuated ||
		gotPolicy.Status.DecisionsTotal != 3 || ks == nil || ks.Status != metav1.ConditionFalse ||
		ks.Reason != string(KillSwitchSentinelDisengaged) {
		t.Fatalf("disengaged status did not resume coherently: %+v", gotPolicy.Status)
	}
	if got := metricValue(t, "phorvex_kill_switch_status_disagreement", map[string]string{
		"namespace": namespace, "policy": policyName,
	}); got != 0 {
		t.Fatalf("successful status reconciliation left disagreement gauge at %v", got)
	}
	e.spec.Mode = v1.ModeDryRun
	snap.Now = now.Add(3 * time.Second)
	m.processTenant(context.Background(), snap, e, false)
	if fa.actuateCalls != 1 || len(notifications.Events) != 1 {
		t.Fatal("dry-run dispatched or emitted notification")
	}

}

func TestKillSwitchStatusDisagreementSurvivesFailedTransition(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ks-alert", Name: "policy"}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1.PhorvexPolicy{}).
		WithObjects(policy).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
				return errors.New("injected status conflict")
			},
		}).Build()
	m := &Manager{Client: c, Log: logr.Discard()}
	m.updateStatus(context.Background(), &policyEntry{
		key: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name},
	}, 1, 1, 0, true, time.Now())
	if got := metricValue(t, "phorvex_kill_switch_status_disagreement", map[string]string{
		"namespace": policy.Namespace, "policy": policy.Name,
	}); got != 1 {
		t.Fatalf("failed kill-switch status transition disagreement gauge = %v, want 1", got)
	}
}

func TestOperationalStatusRetriesConflictAndPreservesControllerCondition(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "status-race", Name: "policy", Generation: 7},
	}
	attempts := 0
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1.PhorvexPolicy{}).
		WithObjects(policy).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, delegate client.Client, subresource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				attempts++
				if attempts == 1 {
					// Simulate the validation reconciler winning the first write. The runner must
					// re-read this status before retrying, or it either drops the kill-switch
					// transition or erases ValidationError with a stale snapshot.
					var concurrent v1.PhorvexPolicy
					if err := delegate.Get(ctx, client.ObjectKeyFromObject(obj), &concurrent); err != nil {
						return err
					}
					meta.SetStatusCondition(&concurrent.Status.Conditions, metav1.Condition{
						Type:               "ValidationError",
						Status:             metav1.ConditionFalse,
						Reason:             "Valid",
						Message:            "policy accepted",
						ObservedGeneration: concurrent.Generation,
					})
					if err := delegate.Status().Update(ctx, &concurrent); err != nil {
						return err
					}
					return apierrors.NewConflict(
						schema.GroupResource{Group: "phorvex.ai", Resource: "phorvexpolicies"},
						obj.GetName(), errors.New("injected concurrent status writer"),
					)
				}
				return delegate.SubResource(subresource).Update(ctx, obj, opts...)
			},
		}).Build()

	m := &Manager{Client: c, Log: logr.Discard()}
	e := &policyEntry{
		key:    types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name},
		tenant: "tenant-a",
	}
	m.updateStatus(context.Background(), e, 3, 1, 0, true, time.Now())

	if attempts != 2 {
		t.Fatalf("status update attempts = %d, want 2 (one conflict and one retry)", attempts)
	}
	var got v1.PhorvexPolicy
	if err := c.Get(context.Background(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	validation := meta.FindStatusCondition(got.Status.Conditions, "ValidationError")
	killSwitch := meta.FindStatusCondition(got.Status.Conditions, "KillSwitch")
	if validation == nil || validation.Status != metav1.ConditionFalse {
		t.Fatalf("runner retry erased the controller-owned ValidationError condition: %+v", got.Status.Conditions)
	}
	if !got.Status.KillSwitchEngaged || killSwitch == nil || killSwitch.Status != metav1.ConditionTrue {
		t.Fatalf("kill-switch transition was lost after status conflict: %+v", got.Status)
	}
	if got.Status.DecisionsTotal != 1 {
		t.Fatalf("conflict retry counted the same decision more than once: got %d, want 1", got.Status.DecisionsTotal)
	}
}
