package actuator

import (
	"context"
	"errors"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

func (c updateFailClient) Update(context.Context, client.Object, ...client.UpdateOption) error {
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
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}, &unstructured.Unstructured{})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, event).Build()
	ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	return c, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, AdapterObservation: &o}
}

func TestAdapterRotateUnloadsPoisonedDegradeToBase(t *testing.T) {
	c, req := trustedAdapterCase(t, false)
	mv := &mockVLLM{}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, req)
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
	_, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, req)
	if err != nil {
		t.Fatalf("adapter-rotate: %v", err)
	}
	// PREMORTEM: reload ONLY from the declared trusted source (never re-pull the poison).
	if mv.unloadCalls != 1 || mv.loadCalls != 1 {
		t.Errorf("must unload(1)+reload-clean(1), got unload=%d load=%d", mv.unloadCalls, mv.loadCalls)
	}
}

func TestAdapterRotateFailClosedNoAdapter(t *testing.T) {
	c := fakeC(aiPod("ns", "infer", map[string]string{})) // no lora-enabled / no adapter
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionAdapterRotate})
	if err != nil || hr.Emitted {
		t.Fatal("adapter-rotate must refuse without trusted observation")
	}
}

func TestAdapterRotateUnreachableIsPending(t *testing.T) {
	c, req := trustedAdapterCase(t, true)
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: &mockVLLM{unloadErr: errStackUnreachable}}, req)
	if err != nil {
		t.Fatalf("unreachable unload must not error: %v", err)
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("note must flag pending, %q", hr.Note)
	}
	// TRUTHFULNESS (same class as the kv-reset fail-closed fix): an eviction without confirmed success
	// is NOT a defence. This branch used to return Emitted:true and stamp an adapter-epoch, marking the
	// decision Actuated and counting it in phorvex_actuations_total while the poisoned adapter was
	// still loaded. Unlike request-drain there is no stack-independent half here — the unload IS the
	// move. No confirmed unload => not emitted, and no epoch (a false forensic record).
	if hr.Emitted {
		t.Errorf("an unconfirmed unload must NOT be reported as emitted, note=%q", hr.Note)
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
	_, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: &mockVLLM{unloadErr: errors.New("HTTP 500")}}, req)
	if err == nil {
		t.Fatal("adapter-rotate must FAIL-CLOSED on a reachable-but-failing unload")
	}
}

// ===== request-drain =====
func TestRequestDrainStopsAdmitsThenAborts(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelServing: "true"})
	c := fakeC(pod)
	mv := &mockVLLM{drained: 3}
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: mv}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionRequestDrain})
	if err != nil {
		t.Fatalf("request-drain: %v", err)
	}
	// ORDERING premortem: admits stopped (label flipped) AND in-flight aborted.
	var p corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	if p.Labels[labelServing] != "drained" {
		t.Errorf("admits must be stopped (serving=drained), got %q", p.Labels[labelServing])
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
	pod := aiPod("ns", "infer", map[string]string{labelServing: "true"})
	c := fakeC(pod)
	if _, err := (requestDrainHandler{}).Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{drained: 1}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionRequestDrain}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	var p corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	stamped := p.Labels[labelDrainEpoch]
	if stamped == "" {
		t.Fatalf("drain-epoch not stamped in the drain Update: %v", p.Labels)
	}
	// Rollback re-admits and must leave the drain-epoch untouched (it records drain EVENTS).
	if err := (requestDrainHandler{}).Rollback(context.Background(), EnactCtx{Client: c}, Request{Namespace: "ns", Pod: "infer"}, ""); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	if p.Labels[labelServing] != "true" {
		t.Errorf("rollback must re-admit (serving=true), got %q", p.Labels[labelServing])
	}
	if p.Labels[labelDrainEpoch] != stamped {
		t.Errorf("rollback changed drain-epoch %q -> %q; it must leave the event clock untouched", stamped, p.Labels[labelDrainEpoch])
	}
}

func TestRequestDrainReachableFailRestoresAdmits(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelServing: "true"})
	c := fakeC(pod)
	_, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{drainErr: errors.New("HTTP 500")}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionRequestDrain})
	if err == nil {
		t.Fatal("request-drain must FAIL-CLOSED on a reachable-but-failing abort")
	}
	var p corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	if p.Labels[labelServing] != "true" {
		t.Errorf("a failed abort must RESTORE admits (not strand the pod unready), got %q", p.Labels[labelServing])
	}
}

func TestRequestDrainUnreachableIsPending(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelServing: "true"})
	c := fakeC(pod)
	hr, err := requestDrainHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{drainErr: errStackUnreachable}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionRequestDrain})
	if err != nil {
		t.Fatalf("unreachable drain must not error (K8s drain real): %v", err)
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("note: %q", hr.Note)
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
	c := fakeC(guardrailPod("ns", "guard", "v1", "v1,v2,v3"))
	mg := &mockGuardrail{}
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Guardrail: mg}, Request{Namespace: "ns", Pod: "guard", Action: model.ActionGuardrailRotate})
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

func TestGuardrailRotateFailClosedNoDistinctVariant(t *testing.T) {
	c := fakeC(guardrailPod("ns", "guard", "v1", "v1")) // only the current variant declared
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Guardrail: &mockGuardrail{}}, Request{Namespace: "ns", Pod: "guard", Action: model.ActionGuardrailRotate})
	if err == nil {
		t.Fatal("guardrail-rotate must FAIL-CLOSED when no DISTINCT variant exists (same blind spot = no MTD)")
	}
}

func TestGuardrailRotateFailClosedNotTier(t *testing.T) {
	c := fakeC(aiPod("ns", "x", map[string]string{}))
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Guardrail: &mockGuardrail{}}, Request{Namespace: "ns", Pod: "x", Action: model.ActionGuardrailRotate})
	if err == nil {
		t.Fatal("guardrail-rotate must FAIL-CLOSED on a non-guardrail pod")
	}
}

func TestGuardrailRotateUnreachableIsNotCreditedOrRecorded(t *testing.T) {
	c := fakeC(guardrailPod("ns", "guard", "v1", "v2"))
	hr, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Guardrail: &mockGuardrail{applyErr: errStackUnreachable}}, Request{Namespace: "ns", Pod: "guard", Action: model.ActionGuardrailRotate})
	if err != nil {
		t.Fatalf("unreachable guardrail must return an honest unconfirmed result: %v", err)
	}
	if hr.Emitted || hr.MutationKind != "none" {
		t.Errorf("unconfirmed live change must not be credited, got emitted=%v mutation=%q", hr.Emitted, hr.MutationKind)
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") || !containsStr(hr.Note, "NOT credited") {
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
	c := fakeC(guardrailPod("ns", "guard", "v1", "v2"))
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Guardrail: &mockGuardrail{applyErr: errors.New("HTTP 500")}}, Request{Namespace: "ns", Pod: "guard", Action: model.ActionGuardrailRotate})
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

func TestGuardrailRotateRestoresLiveVariantWhenRecordFails(t *testing.T) {
	base := fakeC(guardrailPod("ns", "guard", "v1", "v2"))
	c := updateFailClient{Client: base, err: errors.New("Kubernetes write failed")}
	g := &recordingGuardrail{}
	_, err := guardrailRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Guardrail: g}, Request{Namespace: "ns", Pod: "guard", Action: model.ActionGuardrailRotate})
	if err == nil {
		t.Fatal("an unrecordable live transition must fail")
	}
	if len(g.variants) != 2 || g.variants[0] != "v2" || g.variants[1] != "v1" {
		t.Fatalf("failed Kubernetes record must restore live variant v1, apply sequence=%v", g.variants)
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
	pod.Annotations[annoDisaggPeers] = "10.0.0.2:8000,10.0.0.3:8000"
	c := fakeC(pod)
	mk := &mockKVXfer{}
	hr, err := kvMigrateInvalidateHandler{}.Enact(context.Background(), EnactCtx{Client: c, KVXfer: mk}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionKVMigrateInvalidate})
	if err != nil {
		t.Fatalf("kv-migrate-invalidate: %v", err)
	}
	if mk.invCalls != 1 {
		t.Errorf("must invalidate LOCAL KV once, got %d", mk.invCalls)
	}
	// cross-worker is DEFERRED — must be recorded as pending, never claimed done.
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") || !containsStr(hr.Note, "cross-worker") {
		t.Errorf("cross-worker migrate must be recorded as deferred/pending, %q", hr.Note)
	}
}

func TestKVMigrateLocalUnreachablePending(t *testing.T) {
	c := fakeC(aiPod("ns", "infer", map[string]string{"app": "infer"}))
	hr, err := kvMigrateInvalidateHandler{}.Enact(context.Background(), EnactCtx{Client: c, KVXfer: &mockKVXfer{invErr: errStackUnreachable}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionKVMigrateInvalidate})
	if err != nil {
		t.Fatalf("unreachable local invalidate must not error: %v", err)
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
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
	c := fakeC(leader, shadow)
	mv := &mockVLLM{loaded: true, drained: 2}
	hr, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv}, boundReq(leader, model.ActionWarmSwap))
	if err != nil {
		t.Fatalf("warm-swap: %v", err)
	}
	if mv.drainCalls < 1 {
		t.Error("warm-swap must DRAIN the old leader's in-flight before retiring it (the :141 gap)")
	}
	if !containsStr(hr.Note, "drained") {
		t.Errorf("note must record the drain, %q", hr.Note)
	}
}

// ===== build-completion: model-shard-replace TP/PP coherence =====
func tpPod(ns, name, group, rank, role string, loaded bool, size int) *corev1.Pod {
	p := aiPod(ns, name, map[string]string{
		labelParallelGroup: group, labelRank: rank, labelRole: role,
		labelModelShard: "s", labelModelLoaded: bstr(loaded),
	})
	p.Annotations[annoParallelSize] = strconv.Itoa(size)
	return p
}

func TestShardReplaceTPGroupFlipsCoherently(t *testing.T) {
	// a 2-rank TP group: 2 leaders + a COMPLETE replacement shadow group (both ranks ready).
	objs := []client.Object{
		tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
		tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
		tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
		tpPod("ns", "s1", "g", "1", roleShadow, true, 2),
	}
	c := fakeC(objs...)
	// readyErr=unreachable => shadowModelReady falls back to the labelModelLoaded gate (true here).
	hr, err := modelShardReplaceHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, boundReq(objs[0].(*corev1.Pod), model.ActionModelShardReplace))
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

func TestShardReplaceTPFailClosedIncompleteGroup(t *testing.T) {
	// size 2 but only ONE ready shadow rank => must NEVER flip a partial parallel group.
	objs := []client.Object{
		tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
		tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
		tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
		tpPod("ns", "s1", "g", "1", roleShadow, false, 2), // rank 1 NOT ready
	}
	c := fakeC(objs...)
	_, err := modelShardReplaceHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{readyErr: errStackUnreachable}}, boundReq(objs[0].(*corev1.Pod), model.ActionModelShardReplace))
	if err == nil {
		t.Fatal("shard-replace TP/PP must FAIL-CLOSED on an incomplete replacement group")
	}
	// no flip happened: the old leaders survive.
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "l0"}, &p); err != nil {
		t.Error("fail-closed must NOT retire the old group")
	}
}
