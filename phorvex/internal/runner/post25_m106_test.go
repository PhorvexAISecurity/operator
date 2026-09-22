package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type m106RunnerAuthority struct {
	binding model.PersistenceOperationBinding
	allowed model.PersistenceObservation
}

func (m106RunnerAuthority) Source() string { return model.ScopedSessionCapability }
func (a m106RunnerAuthority) AuthorizeObservation(observation model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	return a.binding, reflect.DeepEqual(observation, a.allowed)
}

func TestPost25M106ManagerRegistersExactPolicyEpochWithoutBeliefTraining(t *testing.T) {
	engine := decision.NewCoverageEngine()
	entry := &policyEntry{namespace: "ns", key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "policy-uid", generation: 9, tenant: "tenant"}
	manager := &Manager{Optimizer: engine, policies: map[string]*policyEntry{entry.key.String(): entry}}
	manager.syncOwnerLiveness()

	policy := buildPolicy(entry)
	wantEpoch := model.PolicyEpoch{Namespace: policy.Namespace, Name: policy.PolicyName, UID: policy.PolicyUID, Generation: policy.PolicyGeneration}
	report, allocated := engine.ScopedOutcomeReportFor(policy.Owner())
	if !allocated || report.Source != "none" || report.Disposition != model.PersistenceDispositionNoProducer || report.Policy == nil || *report.Policy != wantEpoch {
		t.Fatalf("manager did not register an empty exact scoped lifecycle: %+v allocated=%t", report, allocated)
	}

	now := time.Date(2026, 9, 20, 23, 0, 0, 0, time.UTC)
	dispatched := now.Add(-62 * time.Second)
	binding := model.PersistenceOperationBinding{
		Policy: wantEpoch, ProcessEpochID: engine.ScopedOutcomeProcessEpochID(), ContractVersion: model.ScopedSessionNativeRotateV1,
		Workload:    model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "deployment-uid"},
		OperationID: "operation", TargetUID: "old-target-uid", Capability: model.ScopedSessionCapability, Action: model.ActionRotate,
		DispatchAcknowledgedAt: dispatched, ObservationNotBefore: dispatched.Add(60 * time.Second), ObservationDeadline: dispatched.Add(65 * time.Second),
		TargetTerminationGraceSeconds: 30,
	}
	observation := model.PersistenceObservation{
		SchemaVersion: model.ScopedOutcomeObservationSchemaV1, Source: model.ScopedSessionCapability,
		ProcessEpochID: binding.ProcessEpochID, ContractVersion: binding.ContractVersion, EvidenceID: "evidence", Policy: wantEpoch,
		Workload: binding.Workload, OperationID: binding.OperationID, TargetUID: binding.TargetUID, Capability: binding.Capability, Action: binding.Action,
		BeforeSHA256: strings.Repeat("a", 64), ActionSHA256: strings.Repeat("b", 64), AfterSHA256: strings.Repeat("c", 64),
		ObservationStart: dispatched.Add(60 * time.Second), ObservationEnd: dispatched.Add(61 * time.Second), Outcome: model.PersistenceHeld,
	}
	engine.Now = func() time.Time { return now }
	engine.PersistenceAuthority = m106RunnerAuthority{binding: binding, allowed: observation}
	alpha, beta := engine.Killchain.Memory.Prior(policy.Owner())
	result := engine.AdmitPersistenceObservation(observation)
	afterAlpha, afterBeta := engine.Killchain.Memory.Prior(policy.Owner())
	if !result.Applied || result.Status.Cohorts[0].Held != 1 || alpha != afterAlpha || beta != afterBeta {
		t.Fatalf("manager epoch report changed attacker-state memory: result=%+v prior=(%g,%g)->(%g,%g)", result, alpha, beta, afterAlpha, afterBeta)
	}
}

type m106NativeActuator struct {
	calls  int
	result *actuator.Result
}

func (*m106NativeActuator) Name() string                                              { return "native" }
func (*m106NativeActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (a *m106NativeActuator) Actuate(_ context.Context, req actuator.Request) (actuator.Result, error) {
	a.calls++
	if a.result != nil {
		return *a.result, nil
	}
	return actuator.Result{Actuator: "native", Handler: string(req.Action), Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/old"}}, nil
}

func TestPost25M106ContradictoryNativeReceiptNeverFeedsProducer(t *testing.T) {
	contradictory := actuator.Result{Actuator: "native", Handler: string(model.ActionRotate), Emitted: true,
		NoEffect: actuator.NoEffectRefused, MutationKind: "forward-only", ObjectsTouched: []string{"Pod/ns/old"}}
	act := &m106NativeActuator{result: &contradictory}
	producer := &m106RunnerProducer{}
	manager := &Manager{Actuator: act, ScopedOutcomeProducer: producer, Log: logr.Discard()}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	entry := &policyEntry{namespace: "ns"}
	views := map[string]*model.WorkloadView{"ns/old": {Pod: model.Pod{Namespace: "ns", Name: "old", UID: "old-uid", Ready: true}}}
	decisions := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "old", Trace: &model.DecisionTraceV2{}}}
	_ = actuateWithBoundary(t, manager, context.Background(), entry, policy, decisions, views)
	if act.calls != 1 || producer.calls != 0 {
		t.Fatalf("contradictory native receipt reached scoped producer: native=%d producer=%d", act.calls, producer.calls)
	}
}
func (*m106NativeActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

type m106RunnerProducer struct {
	calls   int
	request actuator.Request
	result  actuator.Result
}

func (*m106RunnerProducer) Source() string { return model.ScopedSessionCapability }
func (*m106RunnerProducer) AuthorizeObservation(model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	return model.PersistenceOperationBinding{}, false
}
func (p *m106RunnerProducer) RecordNativeRotate(_ model.Policy, _ *model.WorkloadView, req actuator.Request, result actuator.Result, _ time.Time) bool {
	p.calls++
	p.request, p.result = req, result
	return true
}
func (*m106RunnerProducer) Drain(int) []model.ScopedOutcomeDelivery { return nil }

func TestPost25M106ActualNativeDispatchFeedsOnlyNonblockingProducerHook(t *testing.T) {
	act := &m106NativeActuator{}
	producer := &m106RunnerProducer{}
	manager := &Manager{Actuator: act, ScopedOutcomeProducer: producer, Log: logr.Discard()}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	entry := &policyEntry{namespace: "ns"}
	views := map[string]*model.WorkloadView{"ns/old": {Pod: model.Pod{Namespace: "ns", Name: "old", UID: "old-uid", Ready: true}}}
	decisions := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "old", Trace: &model.DecisionTraceV2{}}}
	if n := actuateWithBoundary(t, manager, context.Background(), entry, policy, decisions, views); n != 1 || act.calls != 1 || !decisions[0].Actuated {
		t.Fatalf("native dispatch did not complete: n=%d calls=%d decision=%+v", n, act.calls, decisions[0])
	}
	if producer.calls != 1 || producer.request.TargetUID != "old-uid" || producer.result.Handler != string(model.ActionRotate) {
		t.Fatalf("producer did not receive exact native request/receipt: calls=%d request=%+v result=%+v", producer.calls, producer.request, producer.result)
	}
}

func TestPost25M106ActualHybridNativeRotateFeedsExactReceipt(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, policyv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	controller := true
	replicas := int32(2)
	grace := int64(30)
	owner := &corev1.ReplicationController{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "owner", UID: "owner-uid", ResourceVersion: "3"},
		Spec:       corev1.ReplicationControllerSpec{Replicas: &replicas, Selector: map[string]string{"app": "fixture"}},
		Status:     corev1.ReplicationControllerStatus{Replicas: replicas},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "old", UID: "old-uid", ResourceVersion: "7", Labels: map[string]string{"app": "fixture"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ReplicationController", Name: owner.Name, UID: owner.UID, Controller: &controller}},
	}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &grace}}
	policyObject := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Tenant: "tenant", Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "fixture"}},
		Budget: v1alpha1.BudgetSpec{MaxGracePeriodSeconds: &grace}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	evictions := 0
	cluster := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", UID: "ns-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid"}}, owner, pod, policyObject,
	).WithInterceptorFuncs(interceptor.Funcs{SubResourceCreate: func(ctx context.Context, inner client.Client, name string, obj client.Object, sub client.Object, _ ...client.SubResourceCreateOption) error {
		eviction, ok := sub.(*policyv1.Eviction)
		if name != "eviction" || !ok || eviction.DeleteOptions == nil {
			return context.Canceled
		}
		evictions++
		return inner.Delete(ctx, obj, &client.DeleteOptions{GracePeriodSeconds: eviction.DeleteOptions.GracePeriodSeconds, Preconditions: eviction.DeleteOptions.Preconditions})
	}}).Build()
	hybrid := actuator.NewHybridActuator(cluster)
	hybrid.ConfigureNativeJournal(cluster, "operator")
	producer := &m106RunnerProducer{}
	manager := &Manager{Actuator: hybrid, ScopedOutcomeProducer: producer, BoundaryReader: cluster, Log: logr.Discard()}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1,
		MaxGracePeriodSeconds: grace, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	entry := &policyEntry{namespace: "ns", tenant: "tenant", key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "policy-uid", generation: 1,
		spec: policyObject.Spec}
	views := map[string]*model.WorkloadView{"ns/old": {Pod: model.Pod{Namespace: "ns", Name: "old", UID: "old-uid", Ready: true}}}
	decisions := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "old", Trace: &model.DecisionTraceV2{}}}
	if n, _ := manager.actuatePrepared(t.Context(), entry, policy, decisions, views); n != 1 || evictions != 1 || !decisions[0].Actuated {
		t.Fatalf("hybrid native rotate did not complete: n=%d evictions=%d decision=%+v", n, evictions, decisions[0])
	}
	if producer.calls != 1 || producer.result.Actuator != "native" || producer.result.Handler != string(model.ActionRotate) ||
		producer.request.TargetUID != "old-uid" || len(producer.result.ObjectsTouched) != 1 || producer.result.ObjectsTouched[0] != "Pod/ns/old" {
		t.Fatalf("hybrid receipt did not reach scoped producer exactly: calls=%d request=%+v result=%+v", producer.calls, producer.request, producer.result)
	}
}
