/*
 * Phorvex — M-21 permanent regressions: the SUPPORT CONSUMER.
 *
 * These run the REAL chain — witness → capabilityGaps → debounceActionsSupported →
 * updateStatus — not a method unit test. A truthful SupportsAction that the support check
 * never calls does not close M-21, so every assertion here goes through the actual
 * consumer with a real adapter wired in.
 *
 * RED at f0348b36e12d751a84ffdac1414c6ff6952d2ee1: a fully configured GPU/serving pod on
 * the default Phoenix backend reported ActionsSupported=True for kv-reset, an action that
 * backend's Actuate rejects outright.
 */

package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

// backendWitness wires a REAL selected actuator into the REAL per-tick witness — exactly
// what the production tick does with m.Actuator.
func backendWitness(fleet []model.Pod, act actuator.Actuator) capability.Witness {
	return capability.BuildWitness(context.Background(), capability.BuildIndex(fleet, nil, nil), nil, nil, localActuator(act))
}

func phoenixBackend() actuator.Actuator {
	return actuator.NewPhoenixActuator(fake.NewClientBuilder().Build())
}
func nativeBackend() actuator.Actuator {
	c := fake.NewClientBuilder().Build()
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	native.JournalNamespace = "operator"
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	return native
}

func newEntryManager(t *testing.T, name string) (*Manager, *policyEntry) {
	t.Helper()
	key := types.NamespacedName{Namespace: "ns", Name: name}
	entry := &policyEntry{key: key}
	return &Manager{Local: &inprocess.Services{}, ActionsSupportedDebounce: 3, policies: map[string]*policyEntry{key.String(): entry}}, entry
}

// settle runs the debounce to its threshold so the terminal condition is observed.
func settle(m *Manager, e *policyEntry, run func() capabilityReport) actionsSupportStatus {
	var last actionsSupportStatus
	for i := 0; i < 3; i++ {
		last = m.debounceActionsSupported(e, run())
	}
	return last
}

// --- the headline incident ---

// TestBackendRejectionReachesTheCondition: the false green is gone. A pod that satisfies
// every per-target fixture for kv-reset, on the default Phoenix backend, now reports the
// action unsupported and names the backend and the reason.
func TestBackendRejectionReachesTheCondition(t *testing.T) {
	backend := phoenixBackend()
	pod := model.Pod{Namespace: "ns", Name: "vllm-0", UID: "vllm-0-uid", HasGPU: true, ServingEndpointReady: true}
	views := []*model.WorkloadView{{Pod: pod}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}

	rep := capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, backend))
	if len(rep.gaps) != 1 || rep.gaps[0].action != model.ActionKVReset {
		t.Fatalf("kv-reset must be reported as a gap on phoenix, got %+v", rep.gaps)
	}
	if rep.gaps[0].unsupported != 1 || rep.gaps[0].total != 1 {
		t.Fatalf("a backend rejection applies to every asset, want 1/1, got %d/%d", rep.gaps[0].unsupported, rep.gaps[0].total)
	}
	for _, want := range []string{actuator.ReasonBackendUnsupported, "phoenix", "kv-reset"} {
		if !strings.Contains(rep.gaps[0].why, want) {
			t.Fatalf("the gap reason must name %q, got %q", want, rep.gaps[0].why)
		}
	}

	m, entry := newEntryManager(t, "falsely-green")
	got := settle(m, entry, func() capabilityReport {
		return capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, backend))
	})
	if got.status != metav1.ConditionFalse || got.reason != actionsUnsupportedReason {
		t.Fatalf("condition must flip False, got %s/%s (%s)", got.status, got.reason, got.message)
	}
	if !strings.Contains(got.message, "kv-reset unsupported on 1/1 assets") {
		t.Fatalf("message must carry the count, got %q", got.message)
	}

	// And the claim now agrees with what the backend would actually do.
	if _, err := backend.Actuate(t.Context(), actuator.Request{
		Tenant: "t", Namespace: "ns", Pod: "vllm-0", Action: model.ActionKVReset, Score: 0.9}); err == nil {
		t.Fatal("fixture: phoenix must still reject kv-reset for this test to mean anything")
	}
}

// TestNonAIActionsConsultTheBackend closes the second leg: the old consumer filtered on
// AICapabilityActions, so a native-only K8s move on a Phoenix backend was never examined.
func TestNonAIActionsConsultTheBackend(t *testing.T) {
	backend := phoenixBackend()
	pod := model.Pod{Namespace: "ns", Name: "app-0"}
	views := []*model.WorkloadView{{Pod: pod}}

	for _, a := range []model.Action{model.ActionIdentityRotate, model.ActionRouteRotate,
		model.ActionDebugger, model.ActionCustomInject} {
		if capability.AICapabilityActions[a] {
			t.Fatalf("fixture: %s must be a NON-AI action for this test to mean anything", a)
		}
		pol := model.Policy{EnabledActions: map[model.Action]bool{a: true}}
		witness := backendWitness([]model.Pod{pod}, backend)
		query := views
		if a == model.ActionRouteRotate {
			routePod := model.Pod{Namespace: "ns", Name: "app-0", Ready: true, RouteService: "app-route",
				Labels: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
			peer := routePod
			peer.Name = "app-1"
			service := ingest.ServiceInfo{Namespace: "ns", Name: "app-route", Selector: map[string]string{
				"app": "web", "phorvex.ai/route-key": "old",
			}}
			query = []*model.WorkloadView{{Pod: routePod}}
			witness = capability.BuildWitness(context.Background(), capability.BuildIndex([]model.Pod{routePod, peer}, nil, []ingest.ServiceInfo{service}), nil, nil, localActuator(backend))
		}
		rep := capabilityGaps(pol, query, witness)
		if len(rep.gaps) != 1 || rep.gaps[0].action != a {
			t.Fatalf("%s must be reported unsupported on phoenix, got %+v", a, rep.gaps)
		}
		if !strings.Contains(rep.gaps[0].why, actuator.ReasonBackendUnsupported) {
			t.Fatalf("%s gap must be attributed to the backend, got %q", a, rep.gaps[0].why)
		}
	}
}

// TestMixedPolicyCannotClaimAllSupported: a supported action must not mask a rejected one.
func TestMixedPolicyCannotClaimAllSupported(t *testing.T) {
	backend := phoenixBackend()
	pod := model.Pod{Namespace: "ns", Name: "vllm-0", UID: "vllm-0-uid", HasGPU: true, ServingEndpointReady: true}
	views := []*model.WorkloadView{{Pod: pod}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{
		model.ActionQuarantine: true, // phoenix enacts this
		model.ActionKVReset:    true, // phoenix rejects this
	}}
	rep := capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, backend))
	if len(rep.gaps) != 1 || rep.gaps[0].action != model.ActionKVReset {
		t.Fatalf("exactly kv-reset must be the gap, got %+v", rep.gaps)
	}
	if rep.enabled != 2 {
		t.Fatalf("both enabled actions must be evaluated, got %d", rep.enabled)
	}
	m, entry := newEntryManager(t, "mixed")
	got := settle(m, entry, func() capabilityReport {
		return capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, backend))
	})
	if got.status != metav1.ConditionFalse {
		t.Fatalf("a mixed policy with one rejected action must not claim all-supported, got %s (%s)", got.status, got.message)
	}
	if strings.Contains(got.message, "quarantine unsupported") {
		t.Fatalf("the SUPPORTED action must not be reported as a gap, got %q", got.message)
	}
}

// TestSupportedActionsRemainSupported is the positive control: on a backend that really
// implements the enabled actions, it remains green. The explicit legacy serving mode is
// now appended as an insecure compatibility advisory rather than being hidden.
func TestSupportedActionsRemainSupported(t *testing.T) {
	backend := nativeBackend()
	pod := model.Pod{Namespace: "ns", Name: "vllm-0", UID: "vllm-0-uid", HasGPU: true, ServingEndpointReady: true}
	pod.Ready = true
	pod.RouteService = "app-route"
	pod.Labels = map[string]string{"app": "web", "phorvex.ai/route-key": "old"}
	views := []*model.WorkloadView{{Pod: pod}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{
		model.ActionKVReset: true, model.ActionRouteRotate: true, model.ActionRotate: true,
	}}
	peer := pod
	peer.Name = "vllm-1"
	service := ingest.ServiceInfo{Namespace: "ns", Name: "app-route", Selector: map[string]string{
		"app": "web", "phorvex.ai/route-key": "old",
	}}
	witness := capability.BuildWitness(context.Background(), capability.BuildIndex([]model.Pod{pod, peer}, nil, []ingest.ServiceInfo{service}), nil, nil, localActuator(backend))
	rep := capabilityGaps(pol, views, witness)
	if len(rep.gaps) != 0 {
		t.Fatalf("native implements configured kv-reset, route-rotate and rotate; want no gaps, got %+v", rep.gaps)
	}
	// identity-rotate is now natively implemented: the backend-capability leg reports it
	// capable, so it is NOT a native status gap. Its per-observation / policy-epoch gating
	// is enforced in a separate capability gate leg, not surfaced as a native support gap.
	identity := capabilityGaps(model.Policy{EnabledActions: map[model.Action]bool{model.ActionIdentityRotate: true}}, views, witness)
	if len(identity.gaps) != 0 {
		t.Fatalf("identity-rotate is now natively implemented; it must not be a native status gap, got %+v", identity.gaps)
	}
	m, entry := newEntryManager(t, "green")
	got := m.debounceActionsSupported(entry, rep)
	if got.status != metav1.ConditionTrue ||
		!strings.Contains(got.message, "all enabled actions have matching capabilities in the selected fleet") ||
		!strings.Contains(got.message, "insecure compatibility") || !strings.Contains(got.message, "legacy-plaintext") {
		t.Fatalf("no-gap legacy status must stay green and disclose insecurity, got %s / %q", got.status, got.message)
	}
	// The default pair remains rotate+quarantine. Native supports both; pure
	// Phoenix visibly refuses bounded rotate rather than ignoring its policy cap.
	for _, tc := range []struct {
		backend  actuator.Actuator
		wantGaps int
	}{{phoenixBackend(), 1}, {nativeBackend(), 0}} {
		def := capabilityGaps(model.Policy{}, views, backendWitness([]model.Pod{pod}, tc.backend))
		if len(def.gaps) != tc.wantGaps || (tc.wantGaps == 1 && def.gaps[0].action != model.ActionRotate) {
			t.Fatalf("%s: default action gaps=%+v want rotate-only=%t", tc.backend.Name(), def.gaps, tc.wantGaps == 1)
		}
		if def.enabled != 2 {
			t.Fatalf("%s: a nil EnabledActions map must evaluate the documented default pair, got %d", tc.backend.Name(), def.enabled)
		}
	}
}

// TestPrerequisiteFailuresSurviveBackendAcceptance: backend acceptance must not overwrite
// an existing per-target prerequisite failure. The pod below lacks a Ready serving
// endpoint, and native accepts kv-reset — the CONFIG reason must still be the one reported.
func TestPrerequisiteFailuresSurviveBackendAcceptance(t *testing.T) {
	pod := model.Pod{Namespace: "ns", Name: "no-endpoint", ServingDeclared: true, ServingEndpointReady: false}
	views := []*model.WorkloadView{{Pod: pod}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	rep := capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, nativeBackend()))
	if len(rep.gaps) != 1 {
		t.Fatalf("want the config gap, got %+v", rep.gaps)
	}
	if rep.gaps[0].why != "pod has no Ready serving endpoint" {
		t.Fatalf("the per-target prerequisite must remain the reported reason, got %q", rep.gaps[0].why)
	}
}

// TestUnavailableBackendCannotEstablishSupport: no hands wired, no affirmative support.
func TestUnavailableBackendCannotEstablishSupport(t *testing.T) {
	pod := model.Pod{Namespace: "ns", Name: "vllm-0", HasGPU: true, ServingEndpointReady: true}
	views := []*model.WorkloadView{{Pod: pod}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	rep := capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, nil))
	if len(rep.gaps) != 1 || !strings.Contains(rep.gaps[0].why, actuator.ReasonBackendUnavailable) {
		t.Fatalf("an absent backend must not establish support, got %+v", rep.gaps)
	}
}

// TestEmptyFleetDisclosesAbsentObservation: no assets means nothing was observed, which is
// not the same as everything being ready. It must not claim readiness and must not flip
// the policy to False either (M-20 deliberately does not alert on an empty selection).
func TestEmptyFleetDisclosesAbsentObservation(t *testing.T) {
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	rep := capabilityGaps(pol, nil, backendWitness(nil, nativeBackend()))
	if rep.observed != 0 || rep.enabled != 1 {
		t.Fatalf("empty fleet report = observed %d enabled %d", rep.observed, rep.enabled)
	}
	m, entry := newEntryManager(t, "empty")
	got := m.debounceActionsSupported(entry, rep)
	if got.status != metav1.ConditionUnknown || got.reason != actionsNoAssetsReason {
		t.Fatalf("empty fleet must disclose absent observation, got %s/%s", got.status, got.reason)
	}
	if !strings.Contains(got.message, "no selected assets observed") {
		t.Fatalf("message must say nothing was observed, got %q", got.message)
	}
	if strings.Contains(got.message, "matching capabilities") {
		t.Fatalf("an empty fleet must not assert runtime readiness, got %q", got.message)
	}
	// It must also not consume the transient-loss debounce.
	if entry.actionsUnsupportedTicks != 0 || entry.actionsUnsupportedSignature != "" {
		t.Fatalf("an empty fleet must not arm the capability-loss debounce, got %+v", entry)
	}
}

// TestBackendGapDebouncesLikeAnyOther: a backend rejection is a capability loss like any
// other — it debounces, and it recovers cleanly when the backend changes.
func TestBackendGapDebouncesLikeAnyOther(t *testing.T) {
	pod := model.Pod{Namespace: "ns", Name: "vllm-0", UID: "vllm-0-uid", HasGPU: true, ServingEndpointReady: true}
	views := []*model.WorkloadView{{Pod: pod}}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	m, entry := newEntryManager(t, "debounce")

	onPhoenix := func() capabilityReport {
		return capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, phoenixBackend()))
	}
	for i := 1; i <= 2; i++ {
		got := m.debounceActionsSupported(entry, onPhoenix())
		if got.status != metav1.ConditionUnknown || got.reason != actionsSupportedDegradedReason {
			t.Fatalf("observation %d must debounce, got %s/%s", i, got.status, got.reason)
		}
	}
	if got := m.debounceActionsSupported(entry, onPhoenix()); got.status != metav1.ConditionFalse {
		t.Fatalf("third observation must flip False, got %s", got.status)
	}
	// Switching to a backend that implements the action clears it in one tick.
	recovered := m.debounceActionsSupported(entry, capabilityGaps(pol, views, backendWitness([]model.Pod{pod}, nativeBackend())))
	if recovered.status != metav1.ConditionTrue || entry.actionsUnsupportedTicks != 0 {
		t.Fatalf("recovery on a capable backend must reset, got %+v entry=%+v", recovered, entry)
	}
}

// TestStaleTrueConditionIsCorrected drives the REAL updateStatus path: a policy already
// carrying ActionsSupported=True from an earlier generation must be corrected, with a
// meaningful reason and the current observedGeneration — not left stale.
func TestStaleTrueConditionIsCorrected(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "stale", Generation: 9},
		Status: v1alpha1.PhorvexPolicyStatus{Conditions: []metav1.Condition{{
			Type:               ConditionActionsSupported,
			Status:             metav1.ConditionTrue,
			Reason:             actionsSupportedReason,
			Message:            "all enabled actions have matching capabilities in the selected fleet",
			ObservedGeneration: 4,
			LastTransitionTime: metav1.Now(),
		}}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(policy).Build()

	key := types.NamespacedName{Namespace: "ns", Name: "stale"}
	entry := &policyEntry{key: key, tenant: "t"}
	m := &Manager{Local: &inprocess.Services{}, Client: c, ActionsSupportedDebounce: 1, policies: map[string]*policyEntry{key.String(): entry}}

	pod := model.Pod{Namespace: "ns", Name: "vllm-0", HasGPU: true, ServingEndpointReady: true}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	status := m.debounceActionsSupported(entry,
		capabilityGaps(pol, []*model.WorkloadView{{Pod: pod}}, backendWitness([]model.Pod{pod}, phoenixBackend())))

	m.updateStatus(t.Context(), entry, 1, 0, 0, false, time.Unix(100, 0), status)

	var got v1alpha1.PhorvexPolicy
	if err := c.Get(t.Context(), key, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionActionsSupported)
	if cond == nil {
		t.Fatal("the condition disappeared")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != actionsUnsupportedReason {
		t.Fatalf("the stale True was not corrected: %s/%s", cond.Status, cond.Reason)
	}
	if cond.ObservedGeneration != 9 {
		t.Fatalf("the corrected condition must carry the current generation, got %d", cond.ObservedGeneration)
	}
	if !strings.Contains(cond.Message, "kv-reset") || !strings.Contains(cond.Message, actuator.ReasonBackendUnsupported) {
		t.Fatalf("the corrected message must stay meaningful, got %q", cond.Message)
	}
}

// --- selector wiring through the real constructor ---

// TestNewManagerRefusesInvalidActuatorConfiguration: an unrecognized explicit selector
// must stop construction, so nothing can start reconciling on a substituted backend.
func TestNewManagerRefusesInvalidActuatorConfiguration(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	for _, bad := range []string{"phoenixx", " native", "NATIVE", "   ", "kubectl"} {
		t.Setenv(actuator.BackendEnvVar, bad)
		m, err := newManager(c, logr.Discard())
		if err == nil {
			t.Fatalf("%s=%q must fail construction, got actuator %q", actuator.BackendEnvVar, bad, localServices(m).Actuator.Name())
		}
		if m != nil {
			t.Fatalf("%s=%q returned a Manager alongside the error", actuator.BackendEnvVar, bad)
		}
		if !strings.Contains(err.Error(), actuator.BackendEnvVar) {
			t.Fatalf("the error must name the variable, got %v", err)
		}
	}
}

// TestNewManagerResolvesEveryValidBranch: the documented default is preserved and each
// explicit value selects its own backend.
func TestNewManagerResolvesEveryValidBranch(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	t.Run("omitted-selects-the-default", func(t *testing.T) {
		t.Setenv(actuator.BackendEnvVar, "")
		m, err := newManager(c, logr.Discard())
		if err != nil {
			t.Fatalf("an omitted selector must succeed: %v", err)
		}
		if localServices(m).Actuator.Name() != string(actuator.DefaultBackend) {
			t.Fatalf("omission must select %s, got %s", actuator.DefaultBackend, localServices(m).Actuator.Name())
		}
	})
	for _, want := range []string{"phoenix", "native", "hybrid"} {
		t.Run(want, func(t *testing.T) {
			t.Setenv(actuator.BackendEnvVar, want)
			m, err := newManager(c, logr.Discard())
			if err != nil {
				t.Fatalf("%s must be accepted: %v", want, err)
			}
			if localServices(m).Actuator.Name() != want {
				t.Fatalf("%s selected %s", want, localServices(m).Actuator.Name())
			}
		})
	}
}

// TestBackendResolvedOnceAndShared: the environment is read ONCE, at construction. The
// dispatcher and the support check then read the SAME m.Actuator field, so they can never
// answer for different backends — and a later environment change cannot swap one of them.
func TestBackendResolvedOnceAndShared(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	t.Setenv(actuator.BackendEnvVar, "native")
	m, err := newManager(c, logr.Discard())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(actuator.BackendEnvVar, "hybrid")
	if localServices(m).Actuator.Name() != "native" {
		t.Fatalf("the backend must be resolved once at construction, got %s after the env changed", localServices(m).Actuator.Name())
	}

	// The support consumer must query the instance held in m.Actuator, not a second
	// resolution: swap in a recorder and prove the real status path consults it.
	rec := &recordingBackend{}
	localServices(m).Actuator = rec
	pod := model.Pod{Namespace: "ns", Name: "p", HasGPU: true, ServingEndpointReady: true}
	pol := model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	rep := capabilityGaps(pol, []*model.WorkloadView{{Pod: pod}},
		capability.BuildWitness(t.Context(), capability.BuildIndex([]model.Pod{pod}, nil, nil), nil, nil, localActuator(localServices(m).Actuator)))
	if len(rec.asked) == 0 {
		t.Fatal("the support check never consulted m.Actuator")
	}
	if rec.asked[0] != model.ActionKVReset {
		t.Fatalf("the support check asked about %v, want kv-reset", rec.asked)
	}
	if len(rep.gaps) != 1 || !strings.Contains(rep.gaps[0].why, "recorder-says-no") {
		t.Fatalf("the recorder's answer must be the one that reached the condition, got %+v", rep.gaps)
	}
}

// recordingBackend records which actions the support consumer asked it about.
type recordingBackend struct{ asked []model.Action }

func (*recordingBackend) Name() string                                              { return "recorder" }
func (*recordingBackend) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (*recordingBackend) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}
func (r *recordingBackend) SupportsAction(_ context.Context, a model.Action, _ actuator.Target) (bool, string) {
	r.asked = append(r.asked, a)
	return false, "recorder-says-no"
}

func TestM093ExplicitLegacyModeIsVisibleInActionsSupported(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	native.JournalNamespace = "operator"
	legacy, err := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	if err != nil {
		t.Fatal(err)
	}
	native.SetServingSecurity(legacy)
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "tenant", Name: "model-0", UID: "pod-uid", ServiceAccount: "model-sa", ModelID: "model", Ready: true, ServingDeclared: true, ServingEndpointReady: true}}
	witness := capability.BuildWitness(t.Context(), capability.BuildIndex([]model.Pod{view.Pod}, nil, nil), nil, nil, localActuator(native)).WithPolicyIdentity("policy", "policy-uid")
	report := capabilityGaps(model.Policy{EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}, []*model.WorkloadView{view}, witness)
	manager, entry := newEntryManager(t, "legacy-serving")
	var status actionsSupportStatus
	for range DefaultActionsSupportedDebounceTicks {
		status = manager.debounceActionsSupported(entry, report)
	}
	if status.status != metav1.ConditionTrue || !strings.Contains(status.message, "insecure compatibility") || !strings.Contains(status.message, "legacy-plaintext") {
		t.Fatalf("legacy serving posture was hidden: %+v", status)
	}
}
