package actuator

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// handlers_ai_p4set_test.go — CI coverage for the 4 NEW actuators + the 3 build-completions. K8s
// mechanics run for real (fake client); vLLM/guardrail/KV/MIG calls run through mocks. Fail-closed +
// the premortem properties (no-poison-reload, distinct-variant, stop-admit-ordering, group-coherence)
// are asserted without GPU.

func bstr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type updateFailClient struct {
	client.Client
	err error
}

func (c updateFailClient) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	return c.err
}

type recordingGuardrail struct {
	variants []string
}

func (g *recordingGuardrail) ApplyVariant(_ context.Context, _ servingEndpoint, variant string) error {
	g.variants = append(g.variants, variant)
	return nil
}

// ===== adapter-rotate =====
func adapterPod(ns, name string, clean bool) *corev1.Pod {
	p := aiPod(ns, name, map[string]string{labelLoRAEnabled: "true"})
	p.Annotations[annoLoRAAdapter] = "evil-adapter"
	if clean {
		p.Annotations[annoLoRACleanSource] = "s3://trusted/clean-v2"
	}
	return p
}

func trustedAdapterCase(t *testing.T, clean bool) (client.Client, Request) {
	t.Helper()
	pod, event, o := m95DispatchFixture(t)
	if clean {
		pod.Annotations[annoLoRACleanSource] = "s3://trusted/clean-v2"
	}
	c := fakeC(pod, event)
	ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	return c, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, PolicyName: "policy", PolicyUID: "policy-uid", AdapterObservation: &o}
}

func TestAdapterRotateUnloadsPoisonedDegradeToBase(t *testing.T) {
	c, req := trustedAdapterCase(t, false)
	mv := &mockVLLM{}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv}, req)
	if err != nil {
		t.Fatalf("adapter-rotate: %v", err)
	}
	if mv.unloadCalls != 1 {
		t.Errorf("must UNLOAD the poisoned adapter once, got %d", mv.unloadCalls)
	}
	if mv.loadCalls != 0 {
		t.Errorf("no clean source => must NOT reload (degrade to base), got %d loads", mv.loadCalls)
	}
	if !containsStr(hr.Note, "degraded to base") {
		t.Errorf("note: %q", hr.Note)
	}
}

func TestAdapterRotateReloadsOnlyFromCleanSource(t *testing.T) {
	c, req := trustedAdapterCase(t, true)
	mv := &mockVLLM{}
	_, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv, AdapterSources: AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/clean-v2"}}, req)
	if err != nil {
		t.Fatalf("adapter-rotate: %v", err)
	}
	// PREMORTEM: reload ONLY from the declared trusted source (never re-pull the poison).
	if mv.unloadCalls != 1 || mv.loadCalls != 1 {
		t.Errorf("must unload(1)+reload-clean(1), got unload=%d load=%d", mv.unloadCalls, mv.loadCalls)
	}
	if mv.loadedSource != "/models/clean-v2" {
		t.Fatalf("wrong configured source: %q", mv.loadedSource)
	}
}

func TestAdapterRotateIgnoresAnnotationAndRequiresExactOperatorMapping(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sources AdapterSources
	}{
		{"absent", nil},
		{"wrong-namespace", AdapterSources{adapterSourceKey("other", "evil-adapter"): "/models/approved"}},
		{"wrong-adapter", AdapterSources{adapterSourceKey("ns", "other"): "/models/approved"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, req := trustedAdapterCase(t, true)
			mv := &mockVLLM{}
			hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv, AdapterSources: tc.sources}, req)
			if err != nil || !hr.Emitted || mv.unloadCalls != 1 || mv.loadCalls != 0 || !containsStr(hr.Note, "degraded to base") {
				t.Fatalf("annotation gained reload authority: %+v err=%v calls=%d", hr, err, mv.loadCalls)
			}
		})
	}
}

func TestAdapterRotateConfiguredLoadFailureIsPartial(t *testing.T) {
	c, req := trustedAdapterCase(t, false)
	mv := &mockVLLM{loadErr: errors.New("load failed")}
	s := AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/approved"}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv, AdapterSources: s}, req)
	if err == nil || !hr.Emitted || hr.MutationKind != "partial" || mv.unloadCalls != 1 || mv.loadCalls != 1 {
		t.Fatalf("load partial hidden: %+v err=%v", hr, err)
	}
}

func TestAdapterRotateRollbackRequiresCurrentEvidenceAndMapping(t *testing.T) {
	c, req := trustedAdapterCase(t, false)
	s := AdapterSources{adapterSourceKey(req.Namespace, req.AdapterObservation.AdapterName): "/models/approved"}
	mv := &mockVLLM{}
	if _, err := (adapterRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv, AdapterSources: s}, req); err != nil {
		t.Fatal(err)
	}
	// Compensation must observe the current serving membership, dispatch the
	// approved reload only while absent, then observe exact presence.
	mv.adapterStates = []bool{false, true}
	if err := (adapterRotateHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv, AdapterSources: s}, req, req.Namespace+"/"+req.Pod); err != nil {
		t.Fatalf("authorized compensation refused: %v", err)
	}
	if mv.loadCalls != 2 || mv.loadedSource != "/models/approved" {
		t.Fatalf("compensation did not use current mapping: %+v", mv)
	}
	p := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, p); err != nil {
		t.Fatal(err)
	}
	p.Annotations[annoAdapterSnapshot] = `{"adapter":"forged"}`
	if err := c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := (adapterRotateHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv, AdapterSources: s}, req, ""); err == nil {
		t.Fatal("forged snapshot authorized compensation")
	}
	if mv.loadCalls != 2 {
		t.Fatal("refused compensation reached serving client")
	}
}

func TestAdapterRotateFailClosedNoAdapter(t *testing.T) {
	c := fakeC(aiPod("ns", "infer", map[string]string{})) // no lora-enabled / no adapter
	mv := &mockVLLM{}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionAdapterRotate})
	if err != nil || hr.Emitted || mv.unloadCalls != 0 {
		t.Fatal("adapter-rotate must refuse without trusted observation")
	}
}

func TestAdapterRotateUnreachableIsPending(t *testing.T) {
	c, req := trustedAdapterCase(t, true)
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: &mockVLLM{unloadErr: errStackUnreachable}}, req)
	if err == nil {
		t.Fatal("unreachable unload must surface an incomplete protected operation")
	}
	if !containsStr(hr.Note, "partial or unknown") || hr.MutationKind != "partial" {
		t.Errorf("note must expose protected recovery debt, result=%+v", hr)
	}
	// TRUTHFULNESS: dispatch uncertainty is a visible partial operation so the runner cannot
	// attempt a different fallback, but it is still an error and never receives a success epoch.
	if !hr.Emitted {
		t.Errorf("a dispatched request with unknown outcome must remain visible and block fallback, note=%q", hr.Note)
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Fatalf("pod must still exist: %v", err)
	}
	if p.Annotations["phorvex.ai/adapter-epoch"] != "" {
		t.Error("no adapter-epoch may be written for an unconfirmed unload (false forensic record)")
	}
	if p.Annotations[annoLoRAAdapter] == "" {
		t.Error("the poison marker must be KEPT until eviction is confirmed, so the move is reconciled")
	}
}

func TestAdapterRotateReachableFailFailsClosed(t *testing.T) {
	c, req := trustedAdapterCase(t, true)
	_, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: &mockVLLM{unloadErr: errors.New("HTTP 500")}}, req)
	if err == nil {
		t.Fatal("adapter-rotate must FAIL-CLOSED on a reachable-but-failing unload")
	}
}

// ===== request-drain =====
func TestRequestDrainStopsAdmitsThenAborts(t *testing.T) {
	pod, _, _, c := requestDrainFixture(t, "true")
	mv := &mockVLLM{drained: 3}
	hr, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(c, mv), requestDrainReq(pod))
	if err != nil {
		t.Fatalf("request-drain: %v", err)
	}
	// The endpoint controller observed a transient withdrawal, the stack aborted, and the
	// exact prior serving state was restored before success.
	p := getDrainPod(t, c)
	if p.Labels[labelServing] != "true" || p.Labels[labelDrainEpoch] == "" {
		t.Errorf("exact serving state/operation epoch not preserved: %v", p.Labels)
	}
	if mv.drainCalls != 1 || !containsStr(hr.Note, "3 in-flight aborted") {
		t.Errorf("must abort in-flight via the stack, calls=%d note=%q", mv.drainCalls, hr.Note)
	}
	if !containsStr(hr.Note, "does not block re-entry") {
		t.Errorf("must disclose the re-entry limitation, %q", hr.Note)
	}
}

// TestRequestDrainStampsDrainEpochRollbackUntouched (M-23 A1): request-drain writes an
// event-valued drain-epoch in the SAME Update as the serving flip (the serving label is boolean and
// reverts, so it can't clock repeated drains); Rollback re-admits WITHOUT touching the epoch.
func TestRequestDrainStampsDrainEpochRollbackUntouched(t *testing.T) {
	pod, _, _, c := requestDrainFixture(t, "true")
	hr, err := (requestDrainHandler{}).Enact(context.Background(), requestDrainEC(c, &mockVLLM{drained: 1}), requestDrainReq(pod))
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	p := getDrainPod(t, c)
	stamped := p.Labels[labelDrainEpoch]
	if stamped == "" {
		t.Fatalf("drain-epoch not stamped in the drain Update: %v", p.Labels)
	}
	// Completed operations have no live receipt: a legacy/unbound rollback must refuse and
	// cannot guess a new serving value or rewrite the event epoch.
	if err := (requestDrainHandler{}).Rollback(context.Background(), requestDrainEC(c, nil), requestDrainReq(pod), hr.RollbackRef); err == nil {
		t.Fatal("completed request-drain rollback must not operate without a live protected receipt")
	}
	p = getDrainPod(t, c)
	if p.Labels[labelServing] != "true" {
		t.Errorf("completed drain changed serving state, got %q", p.Labels[labelServing])
	}
	if p.Labels[labelDrainEpoch] != stamped {
		t.Errorf("rollback changed drain-epoch %q -> %q; it must leave the event clock untouched", stamped, p.Labels[labelDrainEpoch])
	}
}

func TestRequestDrainPossibleSendFailureRetainsClosedOperation(t *testing.T) {
	pod, _, _, c := requestDrainFixture(t, "true")
	hr, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(c, &mockVLLM{drainErr: errors.New("HTTP 500")}), requestDrainReq(pod))
	if err == nil {
		t.Fatal("request-drain must FAIL-CLOSED on a reachable-but-failing abort")
	}
	p := getDrainPod(t, c)
	if p.Labels[labelServing] != "drained" {
		t.Errorf("a possible-send failure must retain closed serving state for exact GET recovery, got %q", p.Labels[labelServing])
	}
	if !hr.Emitted {
		t.Fatal("the transient Pod mutation must remain visible alongside the failure")
	}
}

func TestRequestDrainUnreachableIsPending(t *testing.T) {
	pod, _, _, c := requestDrainFixture(t, "true")
	hr, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(c, &mockVLLM{drainErr: errStackUnreachable}), requestDrainReq(pod))
	if err == nil {
		t.Fatal("unreachable drain must not become a successful emission")
	}
	if !containsStr(err.Error(), "GET-only recovery") || !hr.Emitted {
		t.Errorf("result=%+v err=%v", hr, err)
	}
	if got := getDrainPod(t, c).Labels[labelServing]; got != "drained" {
		t.Fatalf("possible-send unreachable drain did not retain closed admission: serving=%q", got)
	}
}

func TestRequestDrainDefinitelyUnsentRestoresAdmits(t *testing.T) {
	pod, _, _, c := requestDrainFixture(t, "true")
	hr, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(c, &mockVLLM{drainErr: &definiteServingUnreachableError{cause: errors.New("dial refused")}}), requestDrainReq(pod))
	if err == nil || !hr.Emitted {
		t.Fatalf("definitely-unsent drain must report the transient mutation and refusal: result=%+v err=%v", hr, err)
	}
	if got := getDrainPod(t, c).Labels[labelServing]; got != "true" {
		t.Fatalf("definitely-unsent drain did not restore exact serving state: serving=%q", got)
	}
}

// ===== guardrail-rotate =====
func guardrailPod(ns, name, cur, alts string) *corev1.Pod {
	p := aiPod(ns, name, map[string]string{labelGuardrailTier: "true"})
	p.Annotations[annoGuardrailVariant] = cur
	p.Annotations[annoGuardrailAlts] = alts
	return p
}

func TestGuardrailRotatePicksDistinctVariant(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v1,v2,v3")
	c := fakeC(pod)
	mg := &mockGuardrail{}
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: mg}, boundReq(pod, model.ActionGuardrailRotate))
	if err != nil {
		t.Fatalf("guardrail-rotate: %v", err)
	}
	// PREMORTEM: must pick a DISTINCT variant (v2, not v1).
	if mg.lastVar != "v2" {
		t.Errorf("must rotate to a DISTINCT variant, got %q", mg.lastVar)
	}
	var p corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "guard"}, &p)
	if p.Annotations[annoGuardrailVariant] != "v2" {
		t.Errorf("variant annotation not re-keyed, got %q", p.Annotations[annoGuardrailVariant])
	}
}

func TestM036GuardrailRotateCyclesCompleteOrderedRoster(t *testing.T) {
	for _, tc := range []struct {
		name, roster string
		want         []string
	}{
		{name: "three-member-wrap", roster: " v1, v2, v2, v3 ", want: []string{"v2", "v3", "v1"}},
		{name: "two-member-alternation", roster: "v1,v2", want: []string{"v2", "v1", "v2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := guardrailPod("ns", "guard", " v1 ", tc.roster)
			c := fakeC(pod)
			controller := &recordingGuardrail{}
			var receiptUID string
			var priorOperation string
			for i, want := range tc.want {
				current := &corev1.Pod{}
				if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
					t.Fatal(err)
				}
				prior := strings.TrimSpace(current.Annotations[annoGuardrailVariant])
				req := boundReq(current, model.ActionGuardrailRotate)
				req.TickID = "m036-cycle-" + strconv.Itoa(i)
				result, err := (guardrailRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: controller}, req)
				if err != nil || !result.Emitted || result.MutationKind != "reversible" {
					t.Fatalf("cycle %d result=%+v err=%v", i, result, err)
				}
				if got := controller.variants[len(controller.variants)-1]; got != want {
					t.Fatalf("cycle %d applied=%q, want %q; all=%v", i, got, want, controller.variants)
				}
				if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
					t.Fatal(err)
				}
				if current.Annotations[annoGuardrailVariant] != want || current.Annotations[annoGuardrailSnap] != prior {
					t.Fatalf("cycle %d metadata current=%q snapshot=%q, want current=%q snapshot=%q", i, current.Annotations[annoGuardrailVariant], current.Annotations[annoGuardrailSnap], want, prior)
				}
				cm, receipt, err := servingReceiptGet(context.Background(), EnactCtx{Reader: c, JournalNamespace: "operator"}, string(pod.UID), model.ActionGuardrailRotate)
				if err != nil || receipt.Phase != "terminal-full" || receipt.Generation != uint64(i+1) || receipt.PriorVariant != prior || receipt.NextVariant != want {
					t.Fatalf("cycle %d receipt=%+v err=%v", i, receipt, err)
				}
				if i == 0 {
					receiptUID = string(cm.UID)
				} else if string(cm.UID) != receiptUID || receipt.OperationID == priorOperation {
					t.Fatalf("cycle %d slot/op identity uid=%q/%q operation=%q prior=%q", i, cm.UID, receiptUID, receipt.OperationID, priorOperation)
				}
				priorOperation = receipt.OperationID

				before := len(controller.variants)
				reconciled, err := (guardrailRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: controller}, req)
				if err != nil || reconciled.Emitted || reconciled.NoEffect != NoEffectReconciled || len(controller.variants) != before {
					t.Fatalf("cycle %d same-operation retry result=%+v calls=%v err=%v", i, reconciled, controller.variants, err)
				}
			}
		})
	}
}

func TestGuardrailRotateFailClosedNoDistinctVariant(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v1")
	c := fakeC(pod) // only the current variant declared
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: &mockGuardrail{}}, boundReq(pod, model.ActionGuardrailRotate))
	if err == nil {
		t.Fatal("guardrail-rotate must FAIL-CLOSED when no DISTINCT variant exists (same blind spot = no MTD)")
	}
}

func TestM036GuardrailRotateRefusesMalformedRosterBeforeReceiptOrEffect(t *testing.T) {
	for _, tc := range []struct {
		name, current, roster string
	}{
		{name: "missing-current", roster: "v1,v2"},
		{name: "current-outside", current: "v3", roster: "v1,v2"},
		{name: "empty-member", current: "v1", roster: "v1,,v2"},
		{name: "singleton", current: "v1", roster: "v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := guardrailPod("ns", "guard", tc.current, tc.roster)
			c := fakeC(pod)
			controller := &recordingGuardrail{}
			result, err := (guardrailRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: controller}, boundReq(pod, model.ActionGuardrailRotate))
			if err == nil || !IsNoEffectRefusal(err) || result.Emitted || len(controller.variants) != 0 {
				t.Fatalf("malformed roster reached effect: result=%+v variants=%v err=%v", result, controller.variants, err)
			}
			var receipts corev1.ConfigMapList
			if err := c.List(context.Background(), &receipts, client.InNamespace("operator")); err != nil || len(receipts.Items) != 0 {
				t.Fatalf("malformed roster created receipt: count=%d err=%v", len(receipts.Items), err)
			}
			current := &corev1.Pod{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
				t.Fatal(err)
			}
			if current.Annotations[annoGuardrailVariant] != tc.current || current.Annotations[annoGuardrailAlts] != tc.roster || current.Annotations[annoGuardrailSnap] != "" || current.Labels["phorvex.ai/guardrail-epoch"] != "" {
				t.Fatalf("malformed roster changed target: labels=%v annotations=%v", current.Labels, current.Annotations)
			}
		})
	}
}

func TestGuardrailRotateFailClosedNotTier(t *testing.T) {
	pod := aiPod("ns", "x", map[string]string{})
	c := fakeC(pod)
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: &mockGuardrail{}}, boundReq(pod, model.ActionGuardrailRotate))
	if err == nil {
		t.Fatal("guardrail-rotate must FAIL-CLOSED on a non-guardrail pod")
	}
}

func TestGuardrailRotateUnreachableIsNotCreditedOrRecorded(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v1,v2")
	c := fakeC(pod)
	hr, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: &mockGuardrail{applyErr: errStackUnreachable}}, boundReq(pod, model.ActionGuardrailRotate))
	if err != nil {
		t.Fatalf("unreachable guardrail must return an honest unconfirmed result: %v", err)
	}
	if hr.Emitted || hr.MutationKind != "none" {
		t.Errorf("unconfirmed live change must not be credited, got emitted=%v mutation=%q", hr.Emitted, hr.MutationKind)
	}
	if !containsStr(hr.Note, "refused before") {
		t.Errorf("note: %q", hr.Note)
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "guard"}, &p); err != nil {
		t.Fatalf("guardrail pod must still exist: %v", err)
	}
	if got := p.Annotations[annoGuardrailVariant]; got != "v1" {
		t.Errorf("unconfirmed change must preserve stored variant v1, got %q", got)
	}
	if p.Annotations[annoGuardrailSnap] != "" {
		t.Error("unconfirmed change must not write a rollback snapshot")
	}
	if p.Labels["phorvex.ai/guardrail-epoch"] != "" {
		t.Error("unconfirmed change must not write a false guardrail epoch")
	}
}

func TestGuardrailRotateReachableFailureDoesNotRecordTransition(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v1,v2")
	c := fakeC(pod)
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", Guardrail: &mockGuardrail{applyErr: errors.New("HTTP 500")}}, boundReq(pod, model.ActionGuardrailRotate))
	if err == nil {
		t.Fatal("reachable guardrail failure must fail closed")
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "guard"}, &p); err != nil {
		t.Fatalf("guardrail pod must still exist: %v", err)
	}
	if got := p.Annotations[annoGuardrailVariant]; got != "v1" {
		t.Errorf("failed live change must preserve stored variant v1, got %q", got)
	}
	if p.Annotations[annoGuardrailSnap] != "" || p.Labels["phorvex.ai/guardrail-epoch"] != "" {
		t.Error("failed live change must not write snapshot or epoch")
	}
}

func TestGuardrailRotateRetainsConfirmedVariantWhenRecordFails(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v1,v2")
	base := fakeC(pod)
	c := updateFailClient{Client: base, err: errors.New("Kubernetes write failed")}
	g := &recordingGuardrail{}
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: base, JournalNamespace: "operator", Guardrail: g}, boundReq(pod, model.ActionGuardrailRotate))
	if err == nil {
		t.Fatal("an unrecordable live transition must fail")
	}
	if len(g.variants) != 1 || g.variants[0] != "v2" {
		t.Fatalf("metadata failure must not issue an unsafe compensating POST, apply sequence=%v", g.variants)
	}
	var p corev1.Pod
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "guard"}, &p); err != nil {
		t.Fatalf("guardrail pod must still exist: %v", err)
	}
	if got := p.Annotations[annoGuardrailVariant]; got != "v1" {
		t.Errorf("failed record must leave stored variant v1, got %q", got)
	}
}

// ===== kv-migrate-invalidate =====
func TestKVMigrateInvalidatesLocalCrossWorkerDeferred(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	pod.Annotations[annoDisaggPeers] = "10.0.0.2:8000,10.0.0.3:8000"
	c := fakeC(pod)
	mk := &mockKVXfer{}
	hr, err := kvMigrateInvalidateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", KVXfer: mk}, boundReq(pod, model.ActionKVMigrateInvalidate))
	if err == nil {
		t.Fatal("deferred cross-worker result must remain an explicit partial error")
	}
	if mk.invCalls != 1 {
		t.Errorf("must invalidate LOCAL KV once, got %d", mk.invCalls)
	}
	// Cross-worker dispatch is unimplemented. The durable receipt and public
	// result must report the exact no-send class rather than claiming completion.
	if !containsStr(hr.Note, "confirmed=0 not-sent-unimplemented=2 refused-before-send=0") {
		t.Errorf("cross-worker migrate must be recorded as deferred/pending, %q", hr.Note)
	}
	if !hr.Emitted || hr.MutationKind != "partial" {
		t.Fatalf("confirmed local invalidation disappeared after deferred remote result: %+v", hr)
	}
	var current corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[annoKVEpoch] != "" || current.Annotations[annoKVLocalEffect] == "" {
		t.Fatalf("local-only outcome minted full session credit: annotations=%v", current.Annotations)
	}
}

func TestKVMigrateLocalUnreachablePending(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	c := fakeC(pod)
	hr, err := kvMigrateInvalidateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", KVXfer: &mockKVXfer{invErr: errStackUnreachable}}, boundReq(pod, model.ActionKVMigrateInvalidate))
	if err != nil {
		t.Fatalf("unreachable local invalidate must not error: %v", err)
	}
	if !containsStr(hr.Note, "refused before") {
		t.Errorf("note: %q", hr.Note)
	}
	// TRUTHFULNESS (same class as the kv-reset fail-closed fix): no invalidation was confirmed — local
	// or remote. This used to return Emitted:true and
	// stamp a kv-epoch, counting a poisoned cache that was never cleared as a real actuation.
	if hr.Emitted {
		t.Errorf("an unconfirmed invalidate must NOT be reported as emitted, note=%q", hr.Note)
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Fatalf("pod must still exist: %v", err)
	}
	if p.Annotations[annoKVEpoch] != "" {
		t.Error("no kv-epoch may be written for an unconfirmed invalidate (false forensic record)")
	}
}

// ===== build-completion: warm-swap REAL drain =====
func TestWarmSwapDrainsOldLeaderBeforeRetire(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	shadow := aiPod("ns", "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	base := fakeC(leader, shadow)
	c := m067ModeledRouteClient(base, leader)
	mv := &mockVLLM{loaded: true, drained: 2}
	hr, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv}, boundReq(leader, model.ActionWarmSwap))
	if err == nil || hr.MutationKind != "swap" {
		t.Fatalf("fake controller must leave replenishment pending after cutover: %+v %v", hr, err)
	}
	if mv.drainCalls < 1 {
		t.Error("warm-swap must DRAIN the old leader's in-flight before retiring it (the :141 gap)")
	}
	if !containsStr(hr.Note, "drained") {
		t.Errorf("note must record the drain, %q", hr.Note)
	}
}

// ===== historical lower-level model-shard TP/PP helper regressions =====
func tpPod(ns, name, group, rank, role string, loaded bool, size int) *corev1.Pod {
	p := aiPod(ns, name, map[string]string{
		labelParallelGroup: group, labelRank: rank, labelRole: role,
		labelModelShard: "s", labelModelLoaded: bstr(loaded),
	})
	p.Annotations[annoParallelSize] = strconv.Itoa(size)
	return p
}

func TestHistoricalShardReplaceTPGroupHelperFlipsCoherently(t *testing.T) {
	// a 2-rank TP group: 2 leaders + a COMPLETE replacement shadow group (both ranks ready).
	objs := []client.Object{
		tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
		tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
		tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
		tpPod("ns", "s1", "g", "1", roleShadow, true, 2),
	}
	c := fakeC(objs...)
	// readyErr=unreachable => shadowModelReady falls back to the labelModelLoaded gate (true here).
	hr, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, boundReq(objs[0].(*corev1.Pod), model.ActionModelShardReplace), "g")
	if err != nil {
		t.Fatalf("shard-replace TP/PP: %v", err)
	}
	// both shadows promoted to leader; both old leaders retired (deleted).
	for _, s := range []string{"s0", "s1"} {
		var p corev1.Pod
		_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: s}, &p)
		if p.Labels[labelRole] != roleLeader {
			t.Errorf("shadow %s not promoted, role=%q", s, p.Labels[labelRole])
		}
	}
	for _, l := range []string{"l0", "l1"} {
		var p corev1.Pod
		if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: l}, &p); err == nil {
			t.Errorf("old leader %s not retired (group must flip coherently)", l)
		}
	}
	if !containsStr(hr.Note, "COHERENTLY") {
		t.Errorf("note: %q", hr.Note)
	}
}

func TestHistoricalShardReplaceTPHelperFailsClosedOnIncompleteGroup(t *testing.T) {
	// size 2 but only ONE ready shadow rank => must NEVER flip a partial parallel group.
	objs := []client.Object{
		tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
		tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
		tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
		tpPod("ns", "s1", "g", "1", roleShadow, false, 2), // rank 1 NOT ready
	}
	c := fakeC(objs...)
	_, err := groupCoherentCutover(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, boundReq(objs[0].(*corev1.Pod), model.ActionModelShardReplace), "g")
	if err == nil {
		t.Fatal("shard-replace TP/PP must FAIL-CLOSED on an incomplete replacement group")
	}
	// no flip happened: the old leaders survive.
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "l0"}, &p); err != nil {
		t.Error("fail-closed must NOT retire the old group")
	}
}
