package runner

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

// supportsAll is an EXPLICIT support double: a backend that implements every action. It
// isolates the CONFIG/RBAC legs from the M-21 backend leg, which has its own tests against
// the real adapters. A nil actuator is no longer usable for this — an absent backend
// cannot establish affirmative support, so it would fail every action for the wrong reason.
type supportsAll struct{}

func (supportsAll) Name() string                                              { return "supports-all" }
func (supportsAll) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (supportsAll) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}
func (supportsAll) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

func capWitness(fleet []model.Pod) capability.Witness {
	// explicit support double (backend leg neutralised), no rbac/installable — config leg only.
	return capability.BuildWitness(context.Background(), capability.BuildIndex(fleet, nil, nil), nil, nil, localActuator(supportsAll{}))
}

// report wraps a synthetic gap list with an observation context for the debounce tests
// that construct gaps directly rather than running the witness.
func report(gaps []actionGap) capabilityReport {
	observed, enabled := 1, 1
	for _, g := range gaps {
		if g.total > observed {
			observed = g.total
		}
	}
	if len(gaps) > enabled {
		enabled = len(gaps)
	}
	return capabilityReport{gaps: gaps, observed: observed, enabled: enabled}
}

// flipNames returns the actions that flip the condition (fully unsupported, ∃ nobody
// eligible) — the M-20 count-aware analog of the old unsupported-names helper.
func flipNames(rep capabilityReport) []string {
	out := make([]string, 0, len(rep.gaps))
	for _, g := range flipGaps(rep.gaps) {
		out = append(out, string(g.action))
	}
	sort.Strings(out)
	return out
}

// TestUnsupportedIsExistsNotOr is the M-20 kill shot (Honest-∃, T1-E test (f)): the
// smeared conjunction. Pod A declares serving but no route Service; pod B declares a route
// Service but no serving context. The fleet has both predicates, but no single pod has both.
// The de-OR'd per-pod ∃ therefore reports endpoint-rotate unsupported.
func TestUnsupportedIsExistsNotOr(t *testing.T) {
	podA := model.Pod{Namespace: "ns", Name: "a", ServingDeclared: true}
	podB := model.Pod{Namespace: "ns", Name: "b", RouteService: "inference"}
	views := []*model.WorkloadView{{Pod: podA}, {Pod: podB}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionEndpointRotate: true}}

	got := flipNames(capabilityGaps(pol, views, capWitness([]model.Pod{podA, podB})))
	if strings.Join(got, ",") != "endpoint-rotate" {
		t.Fatalf("smeared conjunction: want endpoint-rotate unsupported (no single pod fully eligible), got %v", got)
	}
}

// A pod that satisfies kv-reset entirely on its own ⇒ supported (∃ holds), even beside
// ineligible pods — no ∀-strict alert-fatigue.
func TestUnsupportedQuietOnHeterogeneity(t *testing.T) {
	full := model.Pod{Namespace: "ns", Name: "full", HasGPU: true, ServingEndpointReady: true}
	cpu := model.Pod{Namespace: "ns", Name: "cpu"} // ineligible, must not flip the status
	views := []*model.WorkloadView{{Pod: full}, {Pod: cpu}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}

	rep := capabilityGaps(pol, views, capWitness([]model.Pod{full, cpu}))
	if got := flipNames(rep); len(got) != 0 {
		t.Fatalf("a fully-eligible pod should keep kv-reset from FLIPPING; got flip=%v", got)
	}
	// ...but the partial gap is still surfaced (count-while-green): kv-reset on 1 of 2.
	if len(rep.gaps) != 1 || rep.gaps[0].unsupported != 1 || rep.gaps[0].total != 2 {
		t.Fatalf("mixed fleet must surface the partial gap (kv-reset 1/2), got %+v", rep.gaps)
	}
}

// TestCountWhileGreen is the M-20 fix (test b): a MIXED tenant keeps the condition TRUE but
// surfaces the per-asset count in the message; the all-lack tenant flips False with the full count.
// OLD behavior (T1-E): mixed → plain "all enabled actions have matching capabilities" (the RED).
func TestCountWhileGreen(t *testing.T) {
	full := model.Pod{Namespace: "ns", Name: "full", HasGPU: true, ServingEndpointReady: true}
	cpu := model.Pod{Namespace: "ns", Name: "cpu"}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}

	key := types.NamespacedName{Namespace: "ns", Name: "mixed"}
	entry := &policyEntry{key: key}
	m := &Manager{Local: &inprocess.Services{}, ActionsSupportedDebounce: 3, policies: map[string]*policyEntry{key.String(): entry}}

	// Mixed: kv-reset serviceable on 1 of 2 -> stays TRUE, message carries "1/2".
	mixed := m.debounceActionsSupported(entry, capabilityGaps(pol,
		[]*model.WorkloadView{{Pod: full}, {Pod: cpu}}, capWitness([]model.Pod{full, cpu})))
	if mixed.status != metav1.ConditionTrue {
		t.Fatalf("mixed tenant must stay supported (green), got %s", mixed.status)
	}
	if !strings.Contains(mixed.message, "kv-reset unsupported on 1/2 assets") ||
		!strings.HasPrefix(mixed.message, "all enabled actions serviceable;") {
		t.Fatalf("mixed message must count-while-green, got %q", mixed.message)
	}

	// All-lack: 0 of 2 eligible -> flips False after the debounce, message carries "2/2".
	allLack := func() actionsSupportStatus {
		return m.debounceActionsSupported(entry, capabilityGaps(pol,
			[]*model.WorkloadView{{Pod: cpu}, {Pod: cpu}}, capWitness([]model.Pod{cpu})))
	}
	var last actionsSupportStatus
	for i := 0; i < 3; i++ {
		last = allLack()
	}
	if last.status != metav1.ConditionFalse || !strings.Contains(last.message, "kv-reset unsupported on 2/2 assets") {
		t.Fatalf("all-lack tenant must flip False with a 2/2 count, got %s / %q", last.status, last.message)
	}
}

// TestGreenZeroDiffWhenNoGaps pins REQ-1: a fully-supported policy keeps the LEGACY message
// byte-identical (no console diff-noise on deploy). Only gap-carrying green policies get the new form.
func TestGreenZeroDiffWhenNoGaps(t *testing.T) {
	full := model.Pod{Namespace: "ns", Name: "full", HasGPU: true, ServingEndpointReady: true}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	key := types.NamespacedName{Namespace: "ns", Name: "ok"}
	entry := &policyEntry{key: key}
	m := &Manager{Local: &inprocess.Services{}, ActionsSupportedDebounce: 3, policies: map[string]*policyEntry{key.String(): entry}}
	got := m.debounceActionsSupported(entry, capabilityGaps(pol,
		[]*model.WorkloadView{{Pod: full}}, capWitness([]model.Pod{full})))
	if got.status != metav1.ConditionTrue || got.message != "all enabled actions have matching capabilities in the selected fleet" {
		t.Fatalf("no-gap green must keep the legacy message byte-identical, got %s / %q", got.status, got.message)
	}
}

// TestConditionWhyMatchesRecordVocabulary is test (c): the condition's why is the witness predicate
// name — the exact string the generator's gate records as exclusionReason (one wit.Capable source).
func TestConditionWhyMatchesRecordVocabulary(t *testing.T) {
	cpu := model.Pod{Namespace: "ns", Name: "cpu"}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	wit := capWitness([]model.Pod{cpu})
	rep := capabilityGaps(pol, []*model.WorkloadView{{Pod: cpu}}, wit)
	if len(rep.gaps) != 1 {
		t.Fatalf("want one gap, got %+v", rep.gaps)
	}
	_, recordWhy := wit.Capable(&model.WorkloadView{Pod: cpu}, model.ActionKVReset)
	if rep.gaps[0].why != recordWhy {
		t.Fatalf("condition why %q != record why %q — the record and condition must share vocabulary", rep.gaps[0].why, recordWhy)
	}
}

// TestDominantWhyDeterministic pins REQ-2: mode over the unsupported assets, lexical-min tiebreak,
// order-independent — so the flip signature (which embeds the why) can't flap and defeat the debounce.
func TestDominantWhyDeterministic(t *testing.T) {
	if got := dominantWhy(map[string]int{"b-reason": 2, "a-reason": 2, "c-reason": 1}); got != "a-reason" {
		t.Fatalf("tie must break lexically to a-reason, got %q", got)
	}
	if got := dominantWhy(map[string]int{"z": 1, "a": 3}); got != "a" {
		t.Fatalf("mode must win (a=3), got %q", got)
	}
	if got := dominantWhy(nil); got != "no selected pod is eligible" {
		t.Fatalf("empty must yield the default, got %q", got)
	}
}

// TestFlipSignatureCountFree pins the load-bearing invariant (K3 N1): the debounce signature
// depends only on the (action, why) of the fully-unsupported set, NOT the N/M count — so a fleet
// growing while the same actions stay fully unsupported keeps the debounce accumulating, while a
// changed reason resets it.
func TestFlipSignatureCountFree(t *testing.T) {
	at22 := []actionGap{{action: model.ActionKVReset, unsupported: 2, total: 2, why: "x"}}
	at33 := []actionGap{{action: model.ActionKVReset, unsupported: 3, total: 3, why: "x"}}
	if flipSignature(at22) != flipSignature(at33) {
		t.Fatalf("signature must be count-free: %q != %q", flipSignature(at22), flipSignature(at33))
	}
	whyY := []actionGap{{action: model.ActionKVReset, unsupported: 2, total: 2, why: "y"}}
	if flipSignature(at22) == flipSignature(whyY) {
		t.Fatal("a changed why must change the signature (so the debounce resets on a genuine reason change)")
	}
}

func TestActionsSupportedDebouncesAndRecovers(t *testing.T) {
	key := types.NamespacedName{Namespace: "ns", Name: "policy"}
	entry := &policyEntry{key: key}
	m := &Manager{Local: &inprocess.Services{}, ActionsSupportedDebounce: 3, policies: map[string]*policyEntry{key.String(): entry}}
	missing := []actionGap{{action: model.ActionMIGRebind, unsupported: 1, total: 1, why: "no selected pod has a MIG device"}}

	for observation := 1; observation <= 2; observation++ {
		status := m.debounceActionsSupported(entry, report(missing))
		if status.status != metav1.ConditionUnknown || status.reason != actionsSupportedDegradedReason {
			t.Fatalf("observation %d = %s/%s, want Unknown/Degraded", observation, status.status, status.reason)
		}
	}
	status := m.debounceActionsSupported(entry, report(missing))
	if status.status != metav1.ConditionFalse || status.reason != actionsUnsupportedReason {
		t.Fatalf("third observation = %s/%s, want False/%s", status.status, status.reason, actionsUnsupportedReason)
	}
	recovered := m.debounceActionsSupported(entry, report(nil))
	if recovered.status != metav1.ConditionTrue || entry.actionsUnsupportedTicks != 0 {
		t.Fatalf("recovery did not reset debounce: %+v entry=%+v", recovered, entry)
	}
	if again := m.debounceActionsSupported(entry, report(missing)); again.status != metav1.ConditionUnknown {
		t.Fatalf("post-recovery first miss was not debounced: %+v", again)
	}
}

func TestUpsertPreservesDebounceOnlyWithinPolicyGeneration(t *testing.T) {
	m := &Manager{Local: &inprocess.Services{}, policies: map[string]*policyEntry{}}
	// M-140: production policies always carry a UID; Upsert refuses an unidentified owner.
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "policy", UID: "uid-debounce", Generation: 1}}
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
	m := &Manager{Local: &inprocess.Services{}, Client: fakeClient, Recorder: recorder}
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

// --- M-160: the ActionsSupported condition now reflects no-rbac gaps ---

type runnerDenySSAR struct{ deny bool }

func (d runnerDenySSAR) Create(_ context.Context, sar *authzv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authzv1.SelfSubjectAccessReview, error) {
	sar.Status.Allowed = !d.deny
	return sar, nil
}

// TestConditionSurfacesNoRBAC: a pod capable of kv-reset but RBAC-denied must appear as a gap in
// the condition (M-160 part B) — before, the condition read capability only and stayed silent.
func TestConditionSurfacesNoRBAC(t *testing.T) {
	pod := model.Pod{Namespace: "denied", Name: "p", HasGPU: true, ServingEndpointReady: true}
	az := authz.NewCheckerWithClient(runnerDenySSAR{deny: true}, authz.DefaultTTL)
	// Explicit support double so the BACKEND leg cannot mask the RBAC leg under test.
	wit := capability.BuildWitness(context.Background(), capability.BuildIndex([]model.Pod{pod}, nil, nil), nil, capability.CheckerAccess(az), localActuator(supportsAll{}))
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}

	rep := capabilityGaps(pol, []*model.WorkloadView{{Pod: pod}}, wit)
	if len(rep.gaps) != 1 || rep.gaps[0].action != model.ActionKVReset || !strings.HasPrefix(rep.gaps[0].why, "no-rbac:") {
		t.Fatalf("condition must surface the kv-reset no-rbac gap, got %+v", rep.gaps)
	}
}
