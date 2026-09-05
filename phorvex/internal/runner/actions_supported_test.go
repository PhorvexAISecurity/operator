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
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/model"
)

func capWitness(fleet []model.Pod) capability.Witness {
	// no actuator (transport not exercised here), no rbac/installable — capability leg only.
	return capability.BuildWitness(context.Background(), capability.BuildIndex(fleet, nil, nil), nil, nil, nil)
}

func unsupportedNames(items []unsupportedAction) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, string(item.action))
	}
	sort.Strings(out)
	return out
}

// TestUnsupportedIsExistsNotOr is the M-20 kill shot (Honest-∃, T1-E test (f)): the
// smeared conjunction. Pod A has the GPU; pod B has the Ready serving endpoint; NEITHER
// has both. The old fleet-wide OR of independent predicates called kv-reset "supported"
// (some pod has a GPU AND some pod has an endpoint). The de-OR'd per-pod ∃ reports it
// UNSUPPORTED, because no single pod is fully eligible.
func TestUnsupportedIsExistsNotOr(t *testing.T) {
	podA := model.Pod{Namespace: "ns", Name: "a", HasGPU: true, ServingEndpointReady: false}
	podB := model.Pod{Namespace: "ns", Name: "b", HasGPU: false, ServingEndpointReady: true}
	views := []*model.WorkloadView{{Pod: podA}, {Pod: podB}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}

	got := unsupportedNames(unsupportedEnabledActions(pol, views, capWitness([]model.Pod{podA, podB})))
	if strings.Join(got, ",") != "kv-reset" {
		t.Fatalf("smeared conjunction: want kv-reset unsupported (no single pod fully eligible), got %v", got)
	}
}

// A pod that satisfies kv-reset entirely on its own ⇒ supported (∃ holds), even beside
// ineligible pods — no ∀-strict alert-fatigue.
func TestUnsupportedQuietOnHeterogeneity(t *testing.T) {
	full := model.Pod{Namespace: "ns", Name: "full", HasGPU: true, ServingEndpointReady: true}
	cpu := model.Pod{Namespace: "ns", Name: "cpu"} // ineligible, must not flip the status
	views := []*model.WorkloadView{{Pod: full}, {Pod: cpu}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}

	if got := unsupportedNames(unsupportedEnabledActions(pol, views, capWitness([]model.Pod{full, cpu}))); len(got) != 0 {
		t.Fatalf("a fully-eligible pod should make kv-reset supported; got unsupported=%v", got)
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
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(policy).Build()
	recorder := record.NewFakeRecorder(5)
	m := &Manager{Client: fakeClient, Recorder: recorder}
	entry := &policyEntry{key: clientKey(policy), tenant: "tenant"}
	unsupported := actionsSupportStatus{
		status: metav1.ConditionFalse, reason: actionsUnsupportedReason,
		message: "mig-rebind: no selected pod has a MIG device",
	}

	m.updateStatus(context.Background(), entry, 1, 0, 0, false, time.Unix(10, 0), unsupported)
	var got v1alpha1.PhorvexPolicy
	if err := fakeClient.Get(context.Background(), clientKey(policy), &got); err != nil {
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
