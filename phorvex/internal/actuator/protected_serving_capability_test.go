package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type protectedJournalErrorReader struct {
	client.Reader
	err error
}

type protectedJournalBlockingReader struct{ client.Reader }

func (r protectedJournalBlockingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		<-ctx.Done()
		return ctx.Err()
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (r protectedJournalErrorReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		return r.err
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func protectedCapabilityNative(t *testing.T, reader client.Reader) *NativeActuator {
	t.Helper()
	native := NewNativeActuator(nil)
	native.SetBoundaryReader(reader)
	native.JournalNamespace = "operator"
	native.SetServingSecurity(legacyServingSecurityForTest(t))
	return native
}

func protectedCapabilityTarget(pod *corev1.Pod) Target {
	return Target{
		Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID),
		PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: normalizeServiceAccount(pod.Spec.ServiceAccountName),
	}
}

func TestProtectedServingCapabilityExcludesExactPendingDomain(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer", labelGuardrailTier: "true"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	pod.Annotations[annoGuardrailVariant] = "v1"
	pod.Annotations[annoGuardrailAlts] = "v1,v2"
	pending := m064PreparedReceipt(pod, model.ActionKVReset, "capability-pending")
	pending.Phase = "dispatching"
	c := fakeC(m064LiteralReceipt(pending))
	native := protectedCapabilityNative(t, c)
	target := protectedCapabilityTarget(pod)
	before := &corev1.ConfigMap{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: "operator", Name: receiptName(pending)}, before); err != nil {
		t.Fatal(err)
	}

	for _, action := range []model.Action{model.ActionKVReset, model.ActionKVMigrateInvalidate} {
		ok, why := native.SupportsAction(t.Context(), action, target)
		if ok || !strings.Contains(why, "protected-serving-journal") || !strings.Contains(why, kvEffectDomain) || !strings.Contains(why, "dispatching") {
			t.Fatalf("%s pending shared domain support=(%v,%q), want exact preselection exclusion", action, ok, why)
		}
	}
	if ok, why := native.SupportsAction(t.Context(), model.ActionGuardrailRotate, target); !ok {
		t.Fatalf("independent guardrail domain was excluded by KV receipt: %q", why)
	}
	if ok, why := native.SupportsAction(t.Context(), model.ActionRotate, target); !ok {
		t.Fatalf("non-serving action was excluded by KV receipt: %q", why)
	}
	after := &corev1.ConfigMap{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(before), after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only capability gate changed retained receipt: before=%+v after=%+v", before, after)
	}
}

func TestProtectedServingCapabilityAbsentTerminalAndDifferentUIDControls(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	target := protectedCapabilityTarget(pod)

	t.Run("absent", func(t *testing.T) {
		c := fakeC()
		if ok, why := protectedCapabilityNative(t, c).SupportsAction(t.Context(), model.ActionKVReset, target); !ok {
			t.Fatalf("absent slot support=(%v,%q), want eligible", ok, why)
		}
	})

	t.Run("terminal", func(t *testing.T) {
		receipt := m064PreparedReceipt(pod, model.ActionKVReset, "capability-terminal")
		receipt.Phase = "terminal-full"
		current := pod.DeepCopy()
		current.Annotations[annoKVResetEpoch] = receipt.ExpectedReset.Value
		c := fakeC(current, m064LiteralReceipt(receipt))
		if ok, why := protectedCapabilityNative(t, c).SupportsAction(t.Context(), model.ActionKVReset, target); !ok {
			t.Fatalf("coherent terminal slot support=(%v,%q), want eligible", ok, why)
		}
	})

	t.Run("terminal expected state drift", func(t *testing.T) {
		receipt := m064PreparedReceipt(pod, model.ActionKVReset, "capability-terminal-drift")
		receipt.Phase = "terminal-full"
		c := fakeC(pod, m064LiteralReceipt(receipt))
		if ok, why := protectedCapabilityNative(t, c).SupportsAction(t.Context(), model.ActionKVReset, target); ok || !strings.Contains(why, "terminal kv-session-v1 authority or expected state drifted") {
			t.Fatalf("drifted terminal slot support=(%v,%q), want preselection exclusion", ok, why)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod, *operationReceipt)
	}{
		{name: "terminal endpoint drift", mutate: func(current *corev1.Pod, _ *operationReceipt) { current.Status.PodIP = "10.0.0.44" }},
		{name: "terminal security drift", mutate: func(_ *corev1.Pod, receipt *operationReceipt) { receipt.ServingServiceAccount = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := m064PreparedReceipt(pod, model.ActionKVReset, strings.ReplaceAll(tc.name, " ", "-"))
			receipt.Phase = "terminal-full"
			current := pod.DeepCopy()
			current.Annotations[annoKVResetEpoch] = receipt.ExpectedReset.Value
			tc.mutate(current, &receipt)
			ok, why := protectedCapabilityNative(t, fakeC(current, m064LiteralReceipt(receipt))).SupportsAction(t.Context(), model.ActionKVReset, target)
			if ok || !strings.Contains(why, "terminal kv-session-v1 authority or expected state drifted") {
				t.Fatalf("%s support=(%v,%q), want preselection exclusion", tc.name, ok, why)
			}
		})
	}

	t.Run("different target UID", func(t *testing.T) {
		old := pod.DeepCopy()
		old.UID = "old-target-uid"
		receipt := m064PreparedReceipt(old, model.ActionKVReset, "capability-old-target")
		receipt.Phase = "dispatching"
		c := fakeC(m064LiteralReceipt(receipt))
		if ok, why := protectedCapabilityNative(t, c).SupportsAction(t.Context(), model.ActionKVReset, target); !ok {
			t.Fatalf("different target UID support=(%v,%q), want exact-slot isolation", ok, why)
		}
	})
}

func TestProtectedServingCapabilityFailsClosedOnInvalidOrUnreadableExactSlot(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	target := protectedCapabilityTarget(pod)
	valid := m064PreparedReceipt(pod, model.ActionKVReset, "capability-invalid")

	invalidCM := func(mutate func(*operationReceipt)) *corev1.ConfigMap {
		r := valid
		mutate(&r)
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Namespace: "operator", Name: receiptName(valid), UID: "invalid-slot-uid", ResourceVersion: "1",
		}, Data: map[string]string{"receipt": string(encoded)}}
	}

	cases := []struct {
		name string
		cm   *corev1.ConfigMap
	}{
		{"unknown phase", invalidCM(func(r *operationReceipt) { r.Phase = "future-unknown" })},
		{"wrong recorded UID", invalidCM(func(r *operationReceipt) { r.TargetUID = "other-target-uid" })},
		{"wrong recorded domain", invalidCM(func(r *operationReceipt) { r.EffectDomain = guardrailEffectDomain })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := protectedCapabilityNative(t, fakeC(tc.cm)).SupportsAction(t.Context(), model.ActionKVReset, target)
			if ok || !strings.Contains(why, "unreadable or invalid") {
				t.Fatalf("invalid exact slot support=(%v,%q), want fail-closed exclusion", ok, why)
			}
		})
	}

	t.Run("API read error", func(t *testing.T) {
		base := fakeC()
		reader := protectedJournalErrorReader{Reader: base, err: errors.New("bounded API read failed")}
		ok, why := protectedCapabilityNative(t, reader).SupportsAction(t.Context(), model.ActionKVReset, target)
		if ok || !strings.Contains(why, "unreadable or invalid") || strings.Contains(why, "bounded API read failed") {
			t.Fatalf("unreadable exact slot support=(%v,%q), want bounded fail-closed reason", ok, why)
		}
	})

	t.Run("parent cancellation bounds read", func(t *testing.T) {
		base := fakeC()
		reader := protectedJournalBlockingReader{Reader: base}
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		started := time.Now()
		ok, why := protectedCapabilityNative(t, reader).SupportsAction(ctx, model.ActionKVReset, target)
		if elapsed := time.Since(started); ok || elapsed > 500*time.Millisecond || !strings.Contains(why, "unreadable or invalid") {
			t.Fatalf("bounded journal read support=(%v,%q) elapsed=%s", ok, why, elapsed)
		}
	})

	t.Run("missing authority", func(t *testing.T) {
		native := NewNativeActuator(nil)
		native.SetServingSecurity(legacyServingSecurityForTest(t))
		ok, why := native.SupportsAction(t.Context(), model.ActionKVReset, target)
		if ok || !strings.Contains(why, "slot authority is unavailable") {
			t.Fatalf("missing journal authority support=(%v,%q), want fail-closed exclusion", ok, why)
		}
	})
}

func TestProtectedServingCapabilityRaceStillStopsAtDispatch(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	c := fakeC(pod)
	native := protectedCapabilityNative(t, c)
	target := protectedCapabilityTarget(pod)
	if ok, why := native.SupportsAction(t.Context(), model.ActionKVReset, target); !ok {
		t.Fatalf("pre-race absent slot support=(%v,%q)", ok, why)
	}

	pending := m064PreparedReceipt(pod, model.ActionKVReset, "capability-race")
	pending.Phase = "dispatching"
	// A separate API snapshot represents the receipt that won the race after the
	// capability read. The dispatch guard must classify current state, not trust
	// the earlier absence.
	raceClient := fakeC(pod, m064LiteralReceipt(pending))
	stack := &mockVLLM{}
	req := boundReq(pod, model.ActionKVReset)
	req.TickID = "capability-after-race"
	result, err := (kvResetHandler{}).Enact(t.Context(), EnactCtx{Client: raceClient, Reader: raceClient, JournalNamespace: "operator", VLLM: stack}, req)
	if err == nil || stack.resetCalls != 0 || result.MutationKind != "partial" || !strings.Contains(result.Note, "dispatching") {
		t.Fatalf("post-selection race was not stopped by dispatch guard: result=%+v calls=%d err=%v", result, stack.resetCalls, err)
	}
}

func TestProtectedServingCapabilityRemovesPendingCandidateButKeepsAlternative(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	pending := m064PreparedReceipt(pod, model.ActionKVReset, "candidate-pending")
	pending.Phase = "dispatching"
	native := protectedCapabilityNative(t, fakeC(m064LiteralReceipt(pending)))
	view := &model.WorkloadView{
		Pod: model.Pod{
			Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Labels: copyLabels(pod.Labels),
			Ready: true, DesiredReplicas: 2, ReadyReplicas: 2, ServingDeclared: true, ServingEndpointReady: true,
		},
		Phase:       model.PhaseWarm,
		Telemetry:   model.Telemetry{ReqRate: model.PresentSignal(0, "fixture-measured")},
		BlastRadius: 0.5,
		ExposureByVariable: map[string]time.Duration{
			model.VarPodIdentity: 2 * time.Hour,
			model.VarSession:     2 * time.Hour,
		},
	}
	profile, ok := recon.Registry.Default()
	if !ok {
		t.Fatal("default recon profile unavailable")
	}
	deps := actionset.Deps{
		Recon: profile,
		FactContext: func(*model.WorkloadView) recon.FactContext {
			return recon.FactContext{AssetValue: 1, PHold: 0.8, StageUrgency: 0.5, BlastRadius: 0.5}
		},
		ECost:       func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 },
		CHi:         func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 },
		CostCeiling: 1,
		Eligible: func(v *model.WorkloadView, action model.Action, cover []string) *actionset.Eligibility {
			if len(cover) == 0 {
				return &actionset.Eligibility{Excluded: true, Kind: "no-cover", Detail: "no cover"}
			}
			target := Target{Namespace: v.Pod.Namespace, Pod: v.Pod.Name, UID: v.Pod.UID,
				Labels: v.Pod.Labels, PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "default"}
			if supported, why := native.SupportsAction(t.Context(), action, target); !supported {
				return &actionset.Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: why}
			}
			return nil
		},
	}
	policy := model.Policy{
		Tenant: "ns", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid",
		EnabledActions:       map[model.Action]bool{model.ActionKVReset: true, model.ActionRotate: true},
		MinAvailableReplicas: 1, AntiOverRotationWindow: time.Minute, P99Ms: 200, MaxMovesPerTick: 1,
	}
	set := deps.Generate([]*model.WorkloadView{view}, policy)
	foundRotate, foundKVExclusion := false, false
	for _, candidate := range set.Candidates {
		if candidate.Action == model.ActionKVReset {
			t.Fatalf("pending protected action survived into candidates: %+v", candidate)
		}
		foundRotate = foundRotate || candidate.Action == model.ActionRotate
	}
	for _, exclusion := range set.Excluded {
		if exclusion.Action == model.ActionKVReset && exclusion.EligibilityKind == "capability-unsupported" && strings.Contains(exclusion.Reason, kvEffectDomain) {
			foundKVExclusion = true
		}
	}
	if !foundRotate || !foundKVExclusion {
		t.Fatalf("pending domain did not preserve an alternative candidate: rotate=%t kvExclusion=%t set=%+v", foundRotate, foundKVExclusion, set)
	}
}

func TestProtectedServingTerminalGuardrailDriftIsExcludedFromActionSet(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer", labelGuardrailTier: "true"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	pod.Annotations[annoGuardrailVariant] = "pgv1"
	pod.Annotations[annoGuardrailAlts] = "pgv1,pgv2"
	receipt := m064PreparedReceipt(pod, model.ActionGuardrailRotate, "candidate-terminal-drift")
	receipt.Phase = "terminal-full"
	native := protectedCapabilityNative(t, fakeC(pod, m064LiteralReceipt(receipt)))
	// The protected actuator still rejects a drifted terminal receipt directly.
	// The decision action set now excludes cyclic guardrail rotation even earlier:
	// it has no proven bypass-invalidating cover, so its capability leg is not run.
	driftTarget := Target{Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID), Labels: copyLabels(pod.Labels),
		PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "default"}
	if supported, why := native.SupportsAction(t.Context(), model.ActionGuardrailRotate, driftTarget); supported || !strings.Contains(why, guardrailEffectDomain) {
		t.Fatalf("terminal drift was not rejected by protected actuator capability: supported=%t why=%q", supported, why)
	}
	view := &model.WorkloadView{
		Pod: model.Pod{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Labels: copyLabels(pod.Labels),
			Ready: true, DesiredReplicas: 2, ReadyReplicas: 2, ServingDeclared: true, ServingEndpointReady: true},
		Phase: model.PhaseWarm, Telemetry: model.Telemetry{ReqRate: model.PresentSignal(0, "fixture-measured")}, BlastRadius: 0.5,
		Events:             []model.SecurityEventInfo{{Name: "guardrail-signal", UID: "guardrail-event-uid", Type: model.AttackVectorGuardrail, TargetsPod: true}},
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour, model.VarSession: 2 * time.Hour},
	}
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw recon profile unavailable")
	}
	deps := actionset.Deps{
		Recon: profile,
		FactContext: func(*model.WorkloadView) recon.FactContext {
			return recon.FactContext{AssetValue: 1, PHold: 0.8, StageUrgency: 0.5, BlastRadius: 0.5}
		},
		ECost: func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 },
		CHi:   func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 }, CostCeiling: 1,
		Eligible: func(v *model.WorkloadView, action model.Action, cover []string) *actionset.Eligibility {
			if len(cover) == 0 {
				return &actionset.Eligibility{Excluded: true, Kind: "no-cover", Detail: "no cover"}
			}
			target := Target{Namespace: v.Pod.Namespace, Pod: v.Pod.Name, UID: v.Pod.UID, Labels: v.Pod.Labels,
				PolicyName: "policy", PolicyUID: "policy-uid", ServiceAccount: "default"}
			if supported, why := native.SupportsAction(t.Context(), action, target); !supported {
				return &actionset.Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: why}
			}
			return nil
		},
	}
	policy := model.Policy{Tenant: "ns", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid",
		EnabledActions:       map[model.Action]bool{model.ActionGuardrailRotate: true, model.ActionRotate: true},
		MinAvailableReplicas: 1, AntiOverRotationWindow: time.Minute, P99Ms: 200, MaxMovesPerTick: 1}
	set := deps.Generate([]*model.WorkloadView{view}, policy)
	foundRotate, foundGuardrailExclusion := false, false
	for _, candidate := range set.Candidates {
		if candidate.Action == model.ActionGuardrailRotate {
			t.Fatalf("drifted terminal guardrail action survived into candidates: %+v", candidate)
		}
		foundRotate = foundRotate || candidate.Action == model.ActionRotate
	}
	for _, exclusion := range set.Excluded {
		if exclusion.Action == model.ActionGuardrailRotate && exclusion.EligibilityKind == "no-cover" && exclusion.Reason == "no cover" {
			foundGuardrailExclusion = true
		}
	}
	if !foundRotate || !foundGuardrailExclusion {
		t.Fatalf("no-cover guardrail exclusion did not preserve an alternative candidate: rotate=%t guardrailExclusion=%t set=%+v", foundRotate, foundGuardrailExclusion, set)
	}
}
