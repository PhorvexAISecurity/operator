package runner

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type m135RecordingClient struct {
	client.Client
	amtdCreates int
	amtdUpdates int
}

func (c *m135RecordingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*amtdv1beta1.AdaptiveMovingTargetDefense); ok {
		c.amtdCreates++
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *m135RecordingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*amtdv1beta1.AdaptiveMovingTargetDefense); ok {
		c.amtdUpdates++
	}
	return c.Client.Update(ctx, obj, opts...)
}

func m135RunnerScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, v1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func m135Policy(mode string) *v1.PhorvexPolicy {
	return &v1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "idle", Name: "policy", UID: types.UID("policy-uid"), Generation: 4},
		Spec: v1.PhorvexPolicySpec{
			Tenant: "team", Mode: mode,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Actions:  v1.ActionsSpec{Enabled: []v1.ActionType{v1.ActionRotate}},
		},
	}
}

func m135Runner(t *testing.T, policy *v1.PhorvexPolicy) (*Manager, *policyEntry, client.Client, *m135RecordingClient) {
	t.Helper()
	scheme := m135RunnerScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.PhorvexPolicy{}).WithObjects(
		policy,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: policy.Namespace}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
	).Build()
	recording := &m135RecordingClient{Client: base}
	var auditSink bytes.Buffer
	m := &Manager{
		Client: base, BoundaryReader: base,
		Clock: exposure.NewClock(), Intents: exposure.NewIntents(),
		Optimizer: &killSwitchOptimizer{}, Audit: audit.New(logr.Discard(), &auditSink),
		Actuator:   actuator.NewPhoenixActuator(recording),
		KillSwitch: &KillSwitch{Client: base, Namespace: "operator"},
		Log:        logr.Discard(), policies: map[string]*policyEntry{},
	}
	if err := m.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	entry := m.policies[client.ObjectKeyFromObject(policy).String()]
	m.mu.RUnlock()
	if entry == nil {
		t.Fatal("registered policy entry missing")
	}
	return m, entry, base, recording
}

func m135EmptySnapshot(now time.Time) *ingest.Snapshot {
	return &ingest.Snapshot{
		PodByKey: map[string]*model.Pod{}, Graph: graph.Build(graph.Input{}),
		EventByPod:      map[string][]model.SecurityEventInfo{},
		NamespaceDryRun: map[string]model.ActuationBrakeObservation{}, Now: now,
	}
}

func TestM135ActualIdleRunnerRepairsMissingAndDriftWithoutExtraWrites(t *testing.T) {
	policy := m135Policy("active")
	m, entry, base, recording := m135Runner(t, policy)
	now := time.Date(2026, 9, 20, 23, 30, 0, 0, time.UTC)
	snapshot := m135EmptySnapshot(now)

	m.processTenant(t.Context(), snapshot, entry, false)
	if recording.amtdCreates != 1 || recording.amtdUpdates != 0 {
		t.Fatalf("zero-Pod missing maintenance writes create=%d update=%d", recording.amtdCreates, recording.amtdUpdates)
	}
	var standing amtdv1beta1.AdaptiveMovingTargetDefense
	if err := base.Get(t.Context(), client.ObjectKey{Namespace: "idle", Name: "phorvex-idle-team"}, &standing); err != nil {
		t.Fatal(err)
	}
	if standing.Annotations["phorvex.ai/policy-uid"] != "policy-uid" || standing.Annotations["phorvex.ai/policy-generation"] != "4" {
		t.Fatalf("standing owner identity = %#v", standing.Annotations)
	}
	var current v1.PhorvexPolicy
	if err := base.Get(t.Context(), entry.key, &current); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, ConditionStandingPolicy); condition == nil || condition.Reason != "Repaired" || condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != 4 {
		t.Fatalf("missing-repair condition=%+v", condition)
	}

	snapshot.Now = now.Add(time.Second)
	m.processTenant(t.Context(), snapshot, entry, false)
	if recording.amtdCreates != 1 || recording.amtdUpdates != 0 {
		t.Fatalf("in-sync idle tick wrote create=%d update=%d", recording.amtdCreates, recording.amtdUpdates)
	}
	if err := base.Get(t.Context(), entry.key, &current); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, ConditionStandingPolicy); condition == nil || condition.Reason != "InSync" || condition.Status != metav1.ConditionTrue {
		t.Fatalf("in-sync condition=%+v", condition)
	}

	standing.Spec.PodSelector = map[string]string{"app": "drifted"}
	standing.Annotations["example.com/customer"] = "keep"
	if err := base.Update(t.Context(), &standing); err != nil {
		t.Fatal(err)
	}
	recording.amtdUpdates = 0
	snapshot.Now = now.Add(2 * time.Second)
	m.processTenant(t.Context(), snapshot, entry, false)
	if recording.amtdUpdates != 1 {
		t.Fatalf("drifted idle tick updates=%d want 1", recording.amtdUpdates)
	}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(&standing), &standing); err != nil {
		t.Fatal(err)
	}
	if standing.Spec.PodSelector["app"] != "api" || standing.Annotations["example.com/customer"] != "keep" {
		t.Fatalf("owned repair lost desired/unrelated data: %+v", standing)
	}
	if err := base.Get(t.Context(), entry.key, &current); err != nil {
		t.Fatal(err)
	}
	if condition := meta.FindStatusCondition(current.Status.Conditions, ConditionStandingPolicy); condition == nil || condition.Reason != "Repaired" || condition.Status != metav1.ConditionTrue {
		t.Fatalf("drift-repair condition=%+v", condition)
	}
}

type m135Maintainer struct {
	observeCalls, reconcileCalls, ensureCalls, actuateCalls int
	observation                                             actuator.PolicyMaintenanceResult
	reconcile                                               actuator.PolicyMaintenanceResult
	lastTarget                                              actuator.TenantTarget
}

func (*m135Maintainer) Name() string { return "m135-fixture" }
func (m *m135Maintainer) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	m.ensureCalls++
	return nil
}
func (m *m135Maintainer) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (m *m135Maintainer) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	m.actuateCalls++
	return actuator.Result{}, nil
}
func (m *m135Maintainer) ObserveStandingPolicy(context.Context, actuator.TenantTarget) actuator.PolicyMaintenanceResult {
	m.observeCalls++
	return m.observation
}
func (m *m135Maintainer) ReconcileStandingPolicy(_ context.Context, target actuator.TenantTarget) actuator.PolicyMaintenanceResult {
	m.reconcileCalls++
	m.lastTarget = target
	return m.reconcile
}

func m135MaintenanceUnit(t *testing.T, reader client.Reader, maintainer *m135Maintainer, policy *v1.PhorvexPolicy) (*Manager, *policyEntry, model.Policy) {
	t.Helper()
	m := &Manager{
		Client: reader.(client.Client), BoundaryReader: reader, Actuator: maintainer,
		KillSwitch: &KillSwitch{Client: reader, Namespace: "operator"},
		policies:   map[string]*policyEntry{},
	}
	if err := m.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	entry := m.policies[client.ObjectKeyFromObject(policy).String()]
	m.mu.RUnlock()
	return m, entry, buildPolicy(entry)
}

func m135DriftResult() actuator.PolicyMaintenanceResult {
	return actuator.PolicyMaintenanceResult{
		Preparation: actuator.RoutePreparation{NativeSkipped: true},
		Phoenix:     actuator.PolicyRouteMaintenance{State: actuator.PolicyMaintenanceDrifted, Detail: "owned drift"},
		Native:      actuator.PolicyRouteMaintenance{State: actuator.PolicyMaintenanceNotRequired},
	}
}

func TestM135BrakesAndUnavailableGuardsAreReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name                string
		mode                string
		namespaceAnnotation string
		kill                *corev1.ConfigMap
		readerUnavailable   bool
		initialKill         KillSwitchObservation
	}{
		{name: "policy dry-run", mode: "dryRun"},
		{name: "namespace brake", mode: "active", namespaceAnnotation: "true"},
		{name: "kill switch", mode: "active", kill: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: DefaultKillSwitchName}, Data: map[string]string{"engaged": "true"}}},
		{name: "unavailable reader", mode: "active", readerUnavailable: true},
		{name: "late kill switch", mode: "active", kill: &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: DefaultKillSwitchName}, Data: map[string]string{"engaged": "true"}}, initialKill: KillSwitchObservation{Cause: KillSwitchSentinelDisengaged}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := m135Policy(tc.mode)
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "idle"}}
			if tc.namespaceAnnotation != "" {
				ns.Annotations = map[string]string{actuationbrake.NamespaceDryRunAnnotation: tc.namespaceAnnotation}
			}
			objects := []client.Object{policy, ns, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}}
			if tc.kill != nil {
				objects = append(objects, tc.kill)
			}
			base := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(objects...).Build()
			maintainer := &m135Maintainer{observation: m135DriftResult(), reconcile: m135DriftResult()}
			m, entry, pol := m135MaintenanceUnit(t, base, maintainer, policy)
			if tc.readerUnavailable {
				m.BoundaryReader = nil
			}
			initialNamespace := actuationbrake.Namespace(nil)
			if tc.namespaceAnnotation != "" {
				initialNamespace = actuationbrake.Namespace(ns.Annotations)
			}
			killState := &killSwitchTickState{observation: tc.initialKill}
			status, current := m.maintainStandingPolicy(t.Context(), entry, pol, m.ownerEpoch(pol.Owner()), killState, &actuationBrakeTickState{namespace: initialNamespace})
			if !current || maintainer.observeCalls != 1 || maintainer.reconcileCalls != 0 || status.dispatchAllowed {
				t.Fatalf("status=%+v observe=%d reconcile=%d", status, maintainer.observeCalls, maintainer.reconcileCalls)
			}
			condition := standingPolicyCondition(&status, policy.Generation)
			if condition.Reason != "BrakedWithDrift" || condition.Status != metav1.ConditionFalse {
				t.Fatalf("condition=%+v", condition)
			}
		})
	}
}

func TestM135StaleSuccessorAndPolicyReadFailureDoNotReconcile(t *testing.T) {
	policy := m135Policy("active")
	base := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(policy,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "idle"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
	).Build()
	maintainer := &m135Maintainer{observation: m135DriftResult(), reconcile: m135DriftResult()}
	m, entry, pol := m135MaintenanceUnit(t, base, maintainer, policy)

	var successor v1.PhorvexPolicy
	if err := base.Get(t.Context(), entry.key, &successor); err != nil {
		t.Fatal(err)
	}
	successor.UID = types.UID("successor-uid")
	successor.ResourceVersion = ""
	if err := base.Delete(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if err := base.Create(t.Context(), &successor); err != nil {
		t.Fatal(err)
	}
	status, current := m.maintainStandingPolicy(t.Context(), entry, pol, m.ownerEpoch(pol.Owner()), &killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}}, &actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)})
	if current || status.observed || maintainer.reconcileCalls != 0 {
		t.Fatalf("successor accepted status=%+v reconcile=%d", status, maintainer.reconcileCalls)
	}

	readErr := errors.New("policy read unavailable")
	broken := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(policy,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "idle"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
	).WithInterceptorFuncs(interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*v1.PhorvexPolicy); ok {
			return readErr
		}
		return c.Get(ctx, key, obj, opts...)
	}}).Build()
	maintainer = &m135Maintainer{observation: m135DriftResult(), reconcile: m135DriftResult()}
	m, entry, pol = m135MaintenanceUnit(t, broken, maintainer, policy)
	status, current = m.maintainStandingPolicy(t.Context(), entry, pol, m.ownerEpoch(pol.Owner()), &killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}}, &actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)})
	if !current || maintainer.observeCalls != 1 || maintainer.reconcileCalls != 0 || status.dispatchAllowed {
		t.Fatalf("read failure status=%+v observe=%d reconcile=%d", status, maintainer.observeCalls, maintainer.reconcileCalls)
	}
}

func TestM135GenerationAdvanceDoesNotReconcile(t *testing.T) {
	policy := m135Policy("active")
	base := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(policy,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "idle"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
	).Build()
	maintainer := &m135Maintainer{observation: m135DriftResult(), reconcile: m135DriftResult()}
	m, entry, pol := m135MaintenanceUnit(t, base, maintainer, policy)

	var current v1.PhorvexPolicy
	if err := base.Get(t.Context(), entry.key, &current); err != nil {
		t.Fatal(err)
	}
	current.Generation++
	if err := base.Update(t.Context(), &current); err != nil {
		t.Fatal(err)
	}
	status, ownerCurrent := m.maintainStandingPolicy(t.Context(), entry, pol, m.ownerEpoch(pol.Owner()),
		&killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}},
		&actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)})
	if ownerCurrent || status.observed || maintainer.reconcileCalls != 0 {
		t.Fatalf("new generation accepted status=%+v reconcile=%d", status, maintainer.reconcileCalls)
	}
}

func TestM135RunnerSuppliesExactNamespaceTenantOwnerCount(t *testing.T) {
	policy := m135Policy("active")
	base := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(policy,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "idle"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
	).Build()
	maintainer := &m135Maintainer{reconcile: actuator.PolicyMaintenanceResult{
		Phoenix: actuator.PolicyRouteMaintenance{State: actuator.PolicyMaintenanceInSync},
		Native:  actuator.PolicyRouteMaintenance{State: actuator.PolicyMaintenanceNotRequired},
	}}
	m, entry, pol := m135MaintenanceUnit(t, base, maintainer, policy)

	other := m135Policy("active")
	other.Name = "other-policy"
	other.UID = types.UID("other-policy-uid")
	if err := m.Upsert(other); err != nil {
		t.Fatal(err)
	}
	status, current := m.maintainStandingPolicy(t.Context(), entry, pol, m.ownerEpoch(pol.Owner()),
		&killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}},
		&actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)})
	if !current || !status.observed || maintainer.reconcileCalls != 1 {
		t.Fatalf("maintenance status=%+v reconcile=%d", status, maintainer.reconcileCalls)
	}
	if got := maintainer.lastTarget.PolicyOwnerCount; got != 2 {
		t.Fatalf("PolicyOwnerCount=%d want 2", got)
	}
}

func TestM135SelectedDispatchReusesTickPreparation(t *testing.T) {
	policy := m135Policy("active")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "idle", Name: "api-0", UID: types.UID("pod-uid"), Labels: map[string]string{"app": "api"}}}
	base := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(policy, pod,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "idle"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
	).Build()
	maintainer := &m135Maintainer{}
	m, entry, pol := m135MaintenanceUnit(t, base, maintainer, policy)
	m.Log = logr.Discard()
	decisionRow := model.Decision{
		Namespace: "idle", Pod: "api-0", Action: model.ActionRotate,
		Selected: true, Feasible: true,
		Trace: &model.DecisionTraceV2{DispatchOutcome: model.DispatchNotAttempted, DispatchReason: "pending-dispatch"},
	}
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "idle", Name: "api-0", UID: "pod-uid", Labels: map[string]string{"app": "api"},
		Ready: true, DesiredReplicas: 2, ReadyReplicas: 2,
	}}
	preparation := &actuator.RoutePreparation{PhoenixSkipped: true}
	_, returned, attempted := m.actuatePreparedMode(t.Context(), entry, pol, []model.Decision{decisionRow}, map[string]*model.WorkloadView{"idle/api-0": view}, true,
		&killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}},
		&actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)}, preparation)
	if !attempted || returned == nil || maintainer.actuateCalls != 1 {
		t.Fatalf("selected dispatch attempted=%v preparation=%+v actuate=%d", attempted, returned, maintainer.actuateCalls)
	}
	if maintainer.observeCalls != 0 || maintainer.reconcileCalls != 0 || maintainer.ensureCalls != 0 {
		t.Fatalf("selected dispatch prepared twice: observe=%d reconcile=%d ensure=%d", maintainer.observeCalls, maintainer.reconcileCalls, maintainer.ensureCalls)
	}
}

func TestM054HybridRotateUsesOwnerFeasibility(t *testing.T) {
	view := &model.WorkloadView{Pod: model.Pod{
		Ready: true, DesiredReplicas: 2, ReadyReplicas: 2,
	}}
	pol := model.Policy{
		NativeRotate:         actuatorUsesNativeRotate(actuator.NewHybridActuator(nil)),
		MinAvailableReplicas: 1,
	}
	if !pol.NativeRotate {
		t.Fatal("hybrid rotate did not inherit the native ownership guard")
	}
	move := model.Move{Action: model.ActionRotate}
	if verdict := feasibility.Evaluate(view, move, pol); verdict.Feasible || verdict.Reason != "native-rotation-owner: owner-unresolved" {
		t.Fatalf("unresolved hybrid owner verdict = %+v", verdict)
	}

	view.Pod.RotationOwnership = model.RotationOwnership{
		Eligible: true, OwnerUID: "controller-uid", OwnerResourceVersion: "7",
	}
	if verdict := feasibility.Evaluate(view, move, pol); !verdict.Feasible {
		t.Fatalf("eligible hybrid owner was refused: %+v", verdict)
	}
	if actuatorUsesNativeRotate(actuator.NewPhoenixActuator(nil)) {
		t.Fatal("pure Phoenix rotate was incorrectly classified as native")
	}
}
