package runner

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func allAIEnabledPolicy() model.Policy {
	enabled := map[model.Action]bool{}
	for action := range aiCapabilityActions {
		enabled[action] = true
	}
	return model.Policy{Tenant: "tenant", EnabledActions: enabled}
}

func supportedCapabilityFleet() ([]*model.WorkloadView, *ingest.Snapshot) {
	leader := model.Pod{
		Namespace: "ns", Name: "leader", HasGPU: true, MIGDevice: "1g.10gb", ModelID: "model",
		Ready: true, ServingEndpointReady: true, RouteService: "infer", GuardrailVariants: 2,
		Labels: map[string]string{"app": "infer", labelServing: "true", labelLoRAEnabled: "true"},
	}
	swapShadow := model.Pod{
		Namespace: "ns", Name: "swap-shadow", HasGPU: true, ModelID: "model", Ready: true,
		ServingEndpointReady: true,
		Labels:               map[string]string{labelWarmRole: warmShadowRole, labelModelLoaded: "true", labelSwapGroup: "swap-a"},
	}
	shardShadow := model.Pod{
		Namespace: "ns", Name: "shard-shadow", HasGPU: true, ModelID: "model", Ready: true,
		ServingEndpointReady: true,
		Labels:               map[string]string{labelWarmRole: warmShadowRole, labelModelLoaded: "true", labelModelShard: "shard-a"},
	}
	views := []*model.WorkloadView{{Pod: leader}, {Pod: swapShadow}, {Pod: shardShadow}}
	snapshot := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{
			{Name: "gpu-a", Schedulable: true, AllocatableGPU: 1},
			{Name: "gpu-b", Schedulable: true, AllocatableGPU: 1},
		},
		Services: []ingest.ServiceInfo{{
			Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer", labelServing: "true"},
		}},
	}
	return views, snapshot
}

func unsupportedNames(items []unsupportedAction) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, string(item.action))
	}
	sort.Strings(out)
	return out
}

func TestAllEnabledAIActionsSupportedByMeasuredFleet(t *testing.T) {
	views, snapshot := supportedCapabilityFleet()
	if got := unsupportedEnabledActions(allAIEnabledPolicy(), views, snapshot); len(got) != 0 {
		t.Fatalf("fully capable fleet reported unsupported actions: %+v", got)
	}
}

func TestEveryEnabledAIActionNamesItsMissingBaseCapability(t *testing.T) {
	got := unsupportedEnabledActions(allAIEnabledPolicy(), nil, &ingest.Snapshot{})
	if len(got) != len(aiCapabilityActions) {
		t.Fatalf("unsupported actions = %d, want %d: %+v", len(got), len(aiCapabilityActions), got)
	}
	message := unsupportedMessage(got)
	for action := range aiCapabilityActions {
		if !strings.Contains(message, string(action)+":") {
			t.Errorf("message does not name enabled action %q: %s", action, message)
		}
	}
}

func TestSpecificCapabilityPredicates(t *testing.T) {
	tests := []struct {
		name       string
		breakFleet func([]*model.WorkloadView, *ingest.Snapshot)
		want       []string
	}{
		{"mig", func(v []*model.WorkloadView, _ *ingest.Snapshot) { v[0].Pod.MIGDevice = "" }, []string{"mig-rebind"}},
		{"serving-endpoint", func(v []*model.WorkloadView, _ *ingest.Snapshot) {
			for _, view := range v {
				view.Pod.ServingEndpointReady = false
			}
		}, []string{"kv-migrate-invalidate", "kv-reset"}},
		{"lora", func(v []*model.WorkloadView, _ *ingest.Snapshot) { delete(v[0].Pod.Labels, labelLoRAEnabled) }, []string{"adapter-rotate"}},
		{"guardrails", func(v []*model.WorkloadView, _ *ingest.Snapshot) { v[0].Pod.GuardrailVariants = 1 }, []string{"guardrail-rotate"}},
		{"route-service", func(v []*model.WorkloadView, _ *ingest.Snapshot) { v[0].Pod.RouteService = "" }, []string{"endpoint-rotate"}},
		{"serving-selector", func(_ []*model.WorkloadView, s *ingest.Snapshot) { delete(s.Services[0].Selector, labelServing) }, []string{"request-drain"}},
		{"gpu-nodes", func(_ []*model.WorkloadView, s *ingest.Snapshot) { s.Nodes = s.Nodes[:1] }, []string{"model-shard-replace", "warm-swap"}},
		{"warm-pools", func(v []*model.WorkloadView, _ *ingest.Snapshot) {
			v[1].Pod.Labels = map[string]string{}
			v[2].Pod.Labels = map[string]string{}
		}, []string{"model-shard-replace", "warm-swap"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			views, snapshot := supportedCapabilityFleet()
			test.breakFleet(views, snapshot)
			got := unsupportedNames(unsupportedEnabledActions(allAIEnabledPolicy(), views, snapshot))
			if strings.Join(got, ",") != strings.Join(test.want, ",") {
				t.Fatalf("unsupported = %v, want %v", got, test.want)
			}
		})
	}
}

func TestActionsSupportedDebouncesAndRecovers(t *testing.T) {
	key := types.NamespacedName{Namespace: "ns", Name: "policy"}
	entry := &policyEntry{key: key}
	m := &Manager{ActionsSupportedDebounce: 3, policies: map[string]*policyEntry{key.String(): entry}}
	missing := []unsupportedAction{{action: model.ActionMIGRebind, reason: "no selected pod has a MIG device"}}

	for observation := 1; observation <= 2; observation++ {
		status := m.debounceActionsSupported(entry, missing)
		if status.status != metav1.ConditionUnknown || status.reason != actionsSupportedDegradedReason {
			t.Fatalf("observation %d = %s/%s, want Unknown/Degraded", observation, status.status, status.reason)
		}
	}
	status := m.debounceActionsSupported(entry, missing)
	if status.status != metav1.ConditionFalse || status.reason != actionsUnsupportedReason {
		t.Fatalf("third observation = %s/%s, want False/%s", status.status, status.reason, actionsUnsupportedReason)
	}
	recovered := m.debounceActionsSupported(entry, nil)
	if recovered.status != metav1.ConditionTrue || entry.actionsUnsupportedTicks != 0 {
		t.Fatalf("recovery did not reset debounce: %+v entry=%+v", recovered, entry)
	}
	if again := m.debounceActionsSupported(entry, missing); again.status != metav1.ConditionUnknown {
		t.Fatalf("post-recovery first miss was not debounced: %+v", again)
	}
}

func TestUpsertPreservesDebounceOnlyWithinPolicyGeneration(t *testing.T) {
	m := &Manager{policies: map[string]*policyEntry{}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", Generation: 1}}
	if err := m.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	key := clientKey(policy).String()
	m.policies[key].actionsUnsupportedTicks = 2
	m.policies[key].actionsUnsupportedSignature = "same failure"
	if err := m.Upsert(policy.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if m.policies[key].actionsUnsupportedTicks != 2 {
		t.Fatal("same-generation status reconcile reset the debounce counter")
	}
	changed := policy.DeepCopy()
	changed.Generation = 2
	if err := m.Upsert(changed); err != nil {
		t.Fatal(err)
	}
	if m.policies[key].actionsUnsupportedTicks != 0 || m.policies[key].actionsUnsupportedSignature != "" {
		t.Fatal("new policy generation did not reset capability debounce")
	}
}

func TestUnsupportedConditionEmitsOnePolicyEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "policy", Generation: 7,
	}}
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(policy).Build()
	recorder := record.NewFakeRecorder(5)
	m := &Manager{Client: client, Recorder: recorder}
	entry := &policyEntry{key: clientKey(policy), tenant: "tenant"}
	unsupported := actionsSupportStatus{
		status: metav1.ConditionFalse, reason: actionsUnsupportedReason,
		message: "mig-rebind: no selected pod has a MIG device",
	}

	m.updateStatus(context.Background(), entry, 1, 0, 0, false, time.Unix(10, 0), unsupported)
	var got v1alpha1.PhorvexPolicy
	if err := client.Get(context.Background(), clientKey(policy), &got); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(got.Status.Conditions, ConditionActionsSupported)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != actionsUnsupportedReason {
		t.Fatalf("ActionsSupported condition not written: %+v", condition)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, actionsUnsupportedReason) || !strings.Contains(event, "mig-rebind") {
			t.Fatalf("unexpected Event: %s", event)
		}
	default:
		t.Fatal("unsupported condition emitted no Kubernetes Event")
	}

	// The same stable failure must not emit an Event every tick.
	m.updateStatus(context.Background(), entry, 1, 0, 0, false, time.Unix(20, 0), unsupported)
	select {
	case event := <-recorder.Events:
		t.Fatalf("duplicate stable failure emitted another Event: %s", event)
	default:
	}
}

func clientKey(object client.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: object.GetNamespace(), Name: object.GetName()}
}
