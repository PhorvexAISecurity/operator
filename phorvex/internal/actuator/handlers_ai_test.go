package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

// handlers_ai_test.go (P4) — CI coverage for the 5 AI handlers' Enact: the K8s mechanics are exercised
// for REAL against a fake client; the vLLM/MIG calls run through MOCK stack clients so the handler logic
// is validated WITHOUT GPU hardware. Fail-closed paths are asserted on every handler.

// ---- mock stack clients ----
type mockVLLM struct {
	readyErr, resetErr, unloadErr, loadErr, drainErr error
	loaded                                           bool
	drained                                          int
	resetCalls, unloadCalls, loadCalls, drainCalls   int
}

func (m *mockVLLM) ModelReady(_ context.Context, _ servingEndpoint) (bool, error) {
	return m.loaded, m.readyErr
}
func (m *mockVLLM) ResetPrefixCache(_ context.Context, _ servingEndpoint) error {
	m.resetCalls++
	return m.resetErr
}
func (m *mockVLLM) UnloadAdapter(_ context.Context, _ servingEndpoint, _ string) error {
	m.unloadCalls++
	return m.unloadErr
}
func (m *mockVLLM) LoadAdapter(_ context.Context, _ servingEndpoint, _, _ string) error {
	m.loadCalls++
	return m.loadErr
}
func (m *mockVLLM) DrainRequests(_ context.Context, _ servingEndpoint) (int, error) {
	m.drainCalls++
	return m.drained, m.drainErr
}

type mockMIG struct {
	repErr, availErr error
	calls            [][3]string
}

func (m *mockMIG) Available(_ context.Context, _ string) error { return m.availErr }
func (m *mockMIG) CurrentProfile(_ context.Context, _, _ string) (string, error) {
	return "1g.10gb", nil
}
func (m *mockMIG) Repartition(_ context.Context, node, gpu, profile string) error {
	m.calls = append(m.calls, [3]string{node, gpu, profile})
	return m.repErr
}

// ---- mock guardrail + kv-transfer ----
type mockGuardrail struct {
	applyErr   error
	applyCalls int
	lastVar    string
}

func (m *mockGuardrail) ApplyVariant(_ context.Context, _ servingEndpoint, v string) error {
	m.applyCalls++
	m.lastVar = v
	return m.applyErr
}

type mockKVXfer struct {
	invErr, migErr error
	invCalls       int
}

func (m *mockKVXfer) InvalidateLocal(_ context.Context, _ servingEndpoint) error {
	m.invCalls++
	return m.invErr
}
func (m *mockKVXfer) MigrateRemote(_ context.Context, _ servingEndpoint, _ []string) error {
	if m.migErr != nil {
		return m.migErr
	}
	return errors.New("MigrateRemote deferred [PENDING-GPU-VALIDATION]")
}

// ---- pod builders ----
func aiPod(ns, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, ResourceVersion: "7", Labels: labels, Annotations: map[string]string{}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.9",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "vllm", Image: "vllm:latest"}}},
	}
}
func fakeC(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objs...).Build()
}
func leaderRole(p *corev1.Pod) string { return p.Labels[labelRole] }

// ---- warm-swap ----
func TestWarmSwapPromotesRetiresAndRewarms(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	shadow := aiPod("ns", "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	c := fakeC(leader, shadow)
	mv := &mockVLLM{loaded: true}
	hr, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: mv}, Request{Namespace: "ns", Pod: "leader", Action: model.ActionWarmSwap})
	if err != nil {
		t.Fatalf("warm-swap: %v", err)
	}
	if !hr.Emitted || hr.MutationKind != "swap" {
		t.Errorf("warm-swap result: %+v", hr)
	}
	// shadow promoted to leader
	var s corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "shadow"}, &s)
	if leaderRole(&s) != roleLeader {
		t.Errorf("shadow not promoted: role=%q", leaderRole(&s))
	}
	// old leader retired (deleted)
	var old corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "leader"}, &old); err == nil {
		t.Errorf("old leader not retired (still present)")
	}
	// REWARM: a new warm-shadow exists
	var pods corev1.PodList
	_ = c.List(context.Background(), &pods, client.InNamespace("ns"), client.MatchingLabels{labelRole: roleShadow})
	if len(pods.Items) != 1 {
		t.Errorf("REWARM: expected 1 new warm-shadow, got %d", len(pods.Items))
	}
}

func TestWarmSwapFailClosedNoReadyShadow(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	c := fakeC(leader)
	_, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{}}, Request{Namespace: "ns", Pod: "leader", Action: model.ActionWarmSwap})
	if err == nil {
		t.Fatal("warm-swap must FAIL-CLOSED with no Ready shadow")
	}
	var l corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "leader"}, &l)
	if leaderRole(&l) != roleLeader {
		t.Errorf("fail-closed must leave the old leader serving, role=%q", leaderRole(&l))
	}
}

func TestWarmSwapStackUnreachableFallsBackToK8sGate(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	shadow := aiPod("ns", "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	c := fakeC(leader, shadow)
	mv := &mockVLLM{readyErr: errStackUnreachable} // no vLLM stack
	hr, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: mv}, Request{Namespace: "ns", Pod: "leader", Action: model.ActionWarmSwap})
	if err != nil {
		t.Fatalf("warm-swap (unreachable stack, K8s gate): %v", err)
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("unreachable stack must be flagged PENDING-GPU-VALIDATION, note=%q", hr.Note)
	}
}

// ---- kv-reset ----
func TestKVResetRealFlushPodAlive(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{})
	c := fakeC(pod)
	mv := &mockVLLM{}
	hr, err := kvResetHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: mv}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionKVReset})
	if err != nil {
		t.Fatalf("kv-reset: %v", err)
	}
	if mv.resetCalls != 1 {
		t.Errorf("kv-reset must call the REAL vLLM ResetPrefixCache once, got %d", mv.resetCalls)
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Fatal("kv-reset must keep the pod ALIVE (defining property), pod gone")
	}
	if p.Annotations[annoKVResetEpoch] == "" {
		t.Error("kv-reset must record the flush epoch")
	}
	_ = hr
}

func TestKVResetUnreachableIsPendingPodAlive(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{})
	c := fakeC(pod)
	hr, err := kvResetHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{resetErr: errStackUnreachable}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionKVReset})
	if err != nil {
		t.Fatalf("kv-reset (unreachable) must NOT error (pod-alive mechanic real): %v", err)
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("unreachable flush must be flagged pending, note=%q", hr.Note)
	}
	// TRUTHFULNESS: a flush that did not happen is NOT a defence. This branch used to return
	// Emitted:true, which marked the decision Actuated, incremented phorvex_actuations_total, and
	// made the owner lens tell the customer "Cleared injected state on the inference workload" —
	// while no cache was flushed at all. No flush => not emitted.
	if hr.Emitted {
		t.Errorf("unreachable flush must NOT be reported as emitted (it performed nothing), note=%q", hr.Note)
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Error("pod must stay alive")
	}
}

func TestKVResetReachableFailureFailsClosed(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{})
	c := fakeC(pod)
	_, err := kvResetHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{resetErr: errors.New("HTTP 500")}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionKVReset})
	if err == nil {
		t.Fatal("kv-reset must FAIL-CLOSED when a reachable stack rejects the flush (no faked success)")
	}
}

// ---- endpoint-rotate ----
func TestEndpointRotateRestitchesRouteAndRollsBack(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRouteKey: "ep-old"})
	pod.Annotations[annoRouteService] = "infer-svc"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "infer-svc"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{labelRouteKey: "ep-old"}}}
	c := fakeC(pod, svc)
	ec := EnactCtx{Client: c}
	hr, err := endpointRotateHandler{}.Enact(context.Background(), ec, Request{Namespace: "ns", Pod: "infer", Action: model.ActionEndpointRotate})
	if err != nil {
		t.Fatalf("endpoint-rotate: %v", err)
	}
	var p corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	if p.Labels[labelRouteKey] == "ep-old" {
		t.Error("route-key not re-keyed (route did not stale)")
	}
	var s corev1.Service
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer-svc"}, &s)
	if s.Spec.Selector[labelRouteKey] == "ep-old" {
		t.Error("Service selector not restitched to the new route-key")
	}
	// rollback restores the snapshot
	if err := (endpointRotateHandler{}).Rollback(context.Background(), ec, Request{Namespace: "ns", Pod: "infer"}, hr.RollbackRef); err != nil {
		t.Fatalf("endpoint-rotate rollback: %v", err)
	}
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	if p.Labels[labelRouteKey] != "ep-old" {
		t.Errorf("rollback did not restore route-key, got %q", p.Labels[labelRouteKey])
	}
}

// ---- mig-rebind ----
func migPod(ns, name string) *corev1.Pod {
	p := aiPod(ns, name, map[string]string{labelRole: roleLeader})
	p.Annotations[annoGPUID] = "GPU-0"
	p.Annotations[annoMIGProfile] = "2g.20gb"
	p.Spec.Containers[0].Resources.Requests = corev1.ResourceList{"nvidia.com/mig-1g.10gb": resource.MustParse("1")}
	return p
}

func TestMIGRebindRealRepartitionEvictsPod(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	mm := &mockMIG{} // Available nil + Repartition succeeds
	hr, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, MIG: mm, VLLM: &mockVLLM{}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionMIGRebind})
	if err != nil {
		t.Fatalf("mig-rebind: %v", err)
	}
	want := [3]string{"node-a", "GPU-0", "2g.20gb"}
	if len(mm.calls) != 1 || mm.calls[0] != want {
		t.Errorf("mig-rebind must call the REAL Repartition(node,gpu,profile), got %v", mm.calls)
	}
	// GPU-context eviction: the pod must be DELETED (zero CUDA contexts before repartition).
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err == nil {
		t.Error("mig-rebind must EVICT the pod off the GPU (delete) before repartition")
	}
	if !containsStr(hr.Note, "evicted") || !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("note must record eviction + pending, %q", hr.Note)
	}
}

// PHORVEXSEC-121 Mode-C discipline: a failed physical repartition must never be
// reported as an emitted defence. The optimizer may have selected the candidate,
// but manager records actuation/credit only for Emitted=true.
func TestMIGRebindRepartitionFailureEmitsNothing(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	hr, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{
		Client: c,
		MIG:    &mockMIG{repErr: errors.New("live CUDA context blocks repartition")},
		VLLM:   &mockVLLM{},
	}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionMIGRebind})
	if err == nil {
		t.Fatal("failed repartition must return an error")
	}
	if hr.Emitted {
		t.Fatalf("failed repartition received actuation credit: %+v", hr)
	}
}

func TestMIGRebindFailClosedNoDevice(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRole: roleLeader}) // no MIG resource
	c := fakeC(pod)
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, MIG: &mockMIG{}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionMIGRebind})
	if err == nil {
		t.Fatal("mig-rebind must FAIL-CLOSED without a MIG device")
	}
}

// The Available probe must fail-closed BEFORE any destructive eviction (the pod survives).
func TestMIGRebindFailClosedTransportUnavailable(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, MIG: &mockMIG{availErr: errors.New("node-exec not wired")}, VLLM: &mockVLLM{}}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionMIGRebind})
	if err == nil {
		t.Fatal("mig-rebind must FAIL-CLOSED when the node-exec transport is unavailable")
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Error("an unavailable transport must NOT evict the pod (no destructive action before the probe passes)")
	}
}

func TestMIGRebindDefaultRunnerFailsClosed(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	// no MIG injected => the package default (unconfigured nodeRunner) => must fail-closed.
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionMIGRebind})
	if err == nil {
		t.Fatal("mig-rebind with the default unconfigured node runner must FAIL-CLOSED [PENDING-GPU-VALIDATION]")
	}
}

// ---- model-shard-replace ----
func TestModelShardReplaceWarmCutover(t *testing.T) {
	leader := aiPod("ns", "shard0", map[string]string{labelModelShard: "s", labelRole: roleLeader})
	shadow := aiPod("ns", "shard0b", map[string]string{labelModelShard: "s", labelRole: roleShadow, labelModelLoaded: "true"})
	c := fakeC(leader, shadow)
	hr, err := modelShardReplaceHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{loaded: true}}, Request{Namespace: "ns", Pod: "shard0", Action: model.ActionModelShardReplace})
	if err != nil {
		t.Fatalf("model-shard-replace: %v", err)
	}
	if !hr.Emitted {
		t.Error("shard replace should emit")
	}
	var s corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "shard0b"}, &s)
	if leaderRole(&s) != roleLeader {
		t.Errorf("replacement shard not promoted, role=%q", leaderRole(&s))
	}
}

func TestModelShardReplaceFailClosedNoShard(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRole: roleLeader}) // no model-shard label
	c := fakeC(pod)
	_, err := modelShardReplaceHandler{}.Enact(context.Background(), EnactCtx{Client: c}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionModelShardReplace})
	if err == nil {
		t.Fatal("model-shard-replace must FAIL-CLOSED without a declared shard")
	}
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }
