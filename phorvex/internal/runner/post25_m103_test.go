package runner

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/capacity"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
)

func m103RunnerStore(t *testing.T, loseClaimAck bool) (*capacity.Store, client.Client, model.ResourceScope) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	controller := true
	ready := true
	scope := model.ResourceScope{Kind: model.ResourceUnavailableReadyReplica, Namespace: "ns", ServiceName: "serving", ServiceUID: "service-uid", ControllerUID: "controller-uid"}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "serving", UID: "service-uid"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "fixture"}}}
	pods := []client.Object{}
	endpoints := []discoveryv1.Endpoint{}
	for _, item := range []struct{ name, uid, ip string }{{"target", "target-uid", "10.0.0.1"}, {"peer", "peer-uid", "10.0.0.2"}} {
		pods = append(pods, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: item.name, UID: types.UID(item.uid), Labels: map[string]string{"app": "fixture"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "owner", UID: "controller-uid", Controller: &controller}}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}})
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{item.ip}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: item.name, UID: types.UID(item.uid)}})
	}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "serving-1", UID: "slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: "serving"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "serving", UID: "service-uid", Controller: &controller}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: endpoints}
	ledger := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "phorvex-shared-capacity", UID: "ledger-uid", ResourceVersion: "1", Labels: map[string]string{"phorvex.ai/shared-capacity": "v1"}}, Data: map[string]string{"ledger": `{"version":1,"records":{}}`}}
	objects := []client.Object{service, slice, ledger}
	objects = append(objects, pods...)
	builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...)
	if loseClaimAck {
		builder = builder.WithInterceptorFuncs(interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			cm, ok := obj.(*corev1.ConfigMap)
			if !ok || cm.Name != "phorvex-shared-capacity" {
				return c.Update(ctx, obj, opts...)
			}
			var value struct {
				Records map[string]struct {
					Phase string `json:"phase"`
				} `json:"records"`
			}
			if err := json.Unmarshal([]byte(cm.Data["ledger"]), &value); err != nil {
				return err
			}
			claim := false
			for _, record := range value.Records {
				claim = claim || record.Phase == "dispatching"
			}
			if err := c.Update(ctx, obj, opts...); err != nil {
				return err
			}
			if claim {
				return errors.New("simulated lost dispatch-claim acknowledgement")
			}
			return nil
		}})
	}
	c := builder.Build()
	store, err := capacity.NewStore(c, c, "operator")
	if err != nil {
		t.Fatal(err)
	}
	return store, c, scope
}

func m103RunnerDecision(scope model.ResourceScope) ([]model.Decision, map[string]*model.WorkloadView, model.Policy) {
	move := model.ResourceScope{Kind: model.ResourceMoveCount, Namespace: "ns", ControllerUID: "policy-uid"}
	resources := []model.ResourceConsumption{{Scope: move, Units: 1}, {Scope: scope, Units: 1}}
	decision := model.Decision{Tenant: "tenant", Namespace: "ns", Pod: "target", Action: model.ActionRotate, Selected: true, Feasible: true, Engine: "p1-coverage", Resources: resources, Trace: &model.DecisionTraceV2{DecisionID: "m103-operation"}}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "target", UID: "target-uid", Ready: true, DesiredReplicas: 2, ReadyReplicas: 2}}
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	return []model.Decision{decision}, map[string]*model.WorkloadView{"ns/target": view}, policy
}

func TestM103LostClaimAcknowledgementNeverInvokesBackend(t *testing.T) {
	store, c, scope := m103RunnerStore(t, true)
	hands := &m019Hands{result: modelResultEmitted()}
	m := &Manager{Actuator: hands, SharedCapacity: store, Intents: exposure.NewIntents(), Log: logr.Discard()}
	decisions, views, policy := m103RunnerDecision(scope)
	if got := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views); got != 0 {
		t.Fatalf("actuated = %d", got)
	}
	if len(hands.calls) != 0 {
		t.Fatalf("ambiguous claim invoked backend: %v", hands.calls)
	}
	if decisions[0].DispatchOutcome != model.DispatchNotAttempted || decisions[0].DispatchReason != "shared-capacity-claim-unconfirmed" {
		t.Fatalf("claim refusal evidence = %+v", decisions[0])
	}
	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "operator", Name: "phorvex-shared-capacity"}, &cm); err != nil {
		t.Fatal(err)
	}
	if !stringsContainsJSONPhase(cm.Data["ledger"], "dispatching") {
		t.Fatalf("applied-but-unacknowledged claim was released: %s", cm.Data["ledger"])
	}
}

func TestM103FallbackTraceOwnsAndAdjustsBatchResourceUsage(t *testing.T) {
	move := model.ResourceScope{Kind: model.ResourceMoveCount, Namespace: "ns", ControllerUID: "policy-uid"}
	service := model.ResourceScope{Kind: model.ResourceUnavailableReadyReplica, Namespace: "ns", ServiceName: "serving", ServiceUID: "service-uid", ControllerUID: "controller-uid"}
	original := model.Decision{Namespace: "ns", Pod: "target", Action: model.ActionRotate,
		Resources: []model.ResourceConsumption{{Scope: move, Units: 1}, {Scope: service, Units: 1}},
		Trace:     &model.DecisionTraceV2{DecisionID: "decision", Resources: []model.DecisionResourceCapacityV6{{Scope: move, Limit: 2, Selected: 1}, {Scope: service, Limit: 1, Selected: 1}}},
	}
	alternative := decision.Alternative{Action: model.ActionKVReset, Resources: []model.ResourceConsumption{{Scope: move, Units: 1}}}
	fallback := fallbackDecision(original, alternative)
	if original.Trace.Resources[1].Selected != 1 {
		t.Fatalf("fallback mutated original trace resources: %+v", original.Trace.Resources)
	}
	if fallback.Trace == nil || fallback.Trace.Resources[0].Selected != 1 || fallback.Trace.Resources[1].Selected != 0 {
		t.Fatalf("fallback trace did not exchange batch usage: %+v", fallback.Trace)
	}
}

func modelResultEmitted() actuator.Result { return actuator.Result{Emitted: true} }

func stringsContainsJSONPhase(raw, phase string) bool {
	var value struct {
		Records map[string]struct {
			Phase string `json:"phase"`
		} `json:"records"`
	}
	if json.Unmarshal([]byte(raw), &value) != nil {
		return false
	}
	for _, record := range value.Records {
		if record.Phase == phase {
			return true
		}
	}
	return false
}
