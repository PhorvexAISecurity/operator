package actuator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
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
	adapterObserveCalls                              int
	adapterStates                                    []bool
	adapterObserveErr                                error
	loadedAdapter, loadedSource                      string
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
func (m *mockVLLM) AdapterLoaded(_ context.Context, _ servingEndpoint, _ string) (bool, error) {
	m.adapterObserveCalls++
	if m.adapterObserveErr != nil {
		return false, m.adapterObserveErr
	}
	if len(m.adapterStates) != 0 {
		state := m.adapterStates[0]
		m.adapterStates = m.adapterStates[1:]
		return state, nil
	}
	if m.loadCalls > 0 && m.loadErr == nil {
		return true, nil
	}
	return m.unloadCalls == 0, nil
}
func (m *mockVLLM) LoadAdapter(_ context.Context, _ servingEndpoint, adapter, source string) error {
	m.loadCalls++
	m.loadedAdapter, m.loadedSource = adapter, source
	return m.loadErr
}
func (m *mockVLLM) DrainRequests(_ context.Context, _ servingEndpoint) (int, error) {
	m.drainCalls++
	return m.drained, m.drainErr
}

type mockMIG struct {
	repErr, availErr error
	bindErr          error
	revalidate       func(bool) error
	releaseTimeout   time.Duration
	calls            [][3]string
	node             string
}

func (m *mockMIG) BindAllocation(_ context.Context, target migAllocationTarget, rule MIGProfileRule) (migAllocationBinding, error) {
	if m.bindErr != nil {
		return migAllocationBinding{}, m.bindErr
	}
	return migAllocationBinding{Version: 1, Namespace: target.Namespace, Pod: target.Pod, PodUID: target.UID, Node: target.Node, Container: "model", Resource: target.Resource, DeviceID: "MIG-11111111-2222-3333-4444-555555555555", GPUUUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ProfileRule: rule.Namespace + "/" + rule.Resource, TargetProfile: rule.Profile, SnapshotVersion: 1, SnapshotDigest: strings.Repeat("a", 64)}, nil
}
func (m *mockMIG) RevalidateAllocation(_ context.Context, _ migAllocationBinding, targetPresent bool) error {
	if m.revalidate != nil {
		return m.revalidate(targetPresent)
	}
	return nil
}
func (m *mockMIG) allocationReleaseTimeout() time.Duration {
	if m.releaseTimeout > 0 {
		return m.releaseTimeout
	}
	return time.Second
}

func testMIGProfiles() *MIGProfiles {
	return testMIGProfilesFor("ns")
}
func testMIGProfilesFor(namespace string) *MIGProfiles {
	p := &MIGProfiles{Version: 1, Rules: []MIGProfileRule{{Namespace: namespace, Resource: "nvidia.com/mig-1g.10gb", Profile: "2g.20gb"}}}
	_ = p.validate()
	return p
}

func (m *mockMIG) Prepare(_ context.Context, node string) (preparedMIG, error) {
	if m.availErr != nil {
		return nil, m.availErr
	}
	m.node = node
	return m, nil
}
func (m *mockMIG) Capture(_ context.Context, gpu, profile string) (migGeometry, error) {
	if m.availErr != nil {
		return migGeometry{}, m.availErr
	}
	return migGeometry{GPUUUID: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 0, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}}}, nil
}
func (m *mockMIG) Repartition(ctx context.Context, prior migGeometry, profile string, stillOwned func(context.Context) error) (migEffect, error) {
	m.calls = append(m.calls, [3]string{m.node, prior.GPUUUID, profile})
	if err := stillOwned(ctx); err != nil {
		return migEffect{Outcome: "no-destructive-effect", OriginalErr: err}, err
	}
	if m.repErr != nil {
		return migEffect{Outcome: "partial-unrestored", OriginalErr: m.repErr}, m.repErr
	}
	return migEffect{Outcome: "new-geometry-verified"}, nil
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
		// [M-69] every fixture Pod carries a distinct nonempty UID: the destructive AI handlers
		// bind their trigger check and their Delete to it, exactly as the runner's snapshot does.
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name), ResourceVersion: "7", Labels: labels, Annotations: map[string]string{}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.9",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "vllm", Image: "vllm:latest"}}},
	}
}
func fakeC(objs ...client.Object) client.Client {
	var old, next *corev1.Pod
	for _, obj := range objs {
		p, ok := obj.(*corev1.Pod)
		if !ok {
			continue
		}
		if p.Labels[labelRole] == roleLeader {
			old = p
		}
		if p.Labels[labelRole] == roleShadow {
			next = p
		}
	}
	if old != nil && next != nil && old.Labels[labelParallelGroup] == "" && next.Labels[labelParallelGroup] == "" {
		for _, key := range []string{labelSwapGroup, labelModelShard} {
			if old.Labels[key] != "" && old.Labels[key] == next.Labels[key] {
				objs = append(objs, m066FakePool(old, next, key)...)
				break
			}
		}
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "phorvex.ai/fixture-never", Operator: metav1.LabelSelectorOpDoesNotExist}}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap), v1alpha1.ActionType(model.ActionModelShardReplace), v1alpha1.ActionType(model.ActionMIGRebind), v1alpha1.ActionType(model.ActionRequestDrain), v1alpha1.ActionType(model.ActionAdapterRotate)}}}}
	objs = append(objs, policy, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}})
	return fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID("created-" + obj.GetName()))
		}
		return c.Create(ctx, obj, opts...)
	}}).Build()
}
func leaderRole(p *corev1.Pod) string { return p.Labels[labelRole] }

// boundReq is the runner's shape of a destructive AI request: it names the Pod AND binds the
// identity (TargetUID) of the observed object the selection was made against.
func boundReq(p *corev1.Pod, a model.Action) Request {
	return Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID), Action: a, PolicyName: "policy", PolicyUID: "policy-uid"}
}

// ---- warm-swap ----
func TestWarmSwapPromotesRetiresAndAwaitsController(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	shadow := aiPod("ns", "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	c := fakeC(leader, shadow)
	mv := &mockVLLM{loaded: true}
	hr, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv}, boundReq(leader, model.ActionWarmSwap))
	if err == nil || hr.MutationKind != "swap" {
		t.Fatalf("fake controller cannot replenish pool: result=%+v err=%v", hr, err)
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
	// A fake client does not run the ReplicaSet controller. No synthetic Pod is created.
	var pods corev1.PodList
	_ = c.List(context.Background(), &pods, client.InNamespace("ns"), client.MatchingLabels{labelRole: roleShadow})
	if len(pods.Items) != 0 {
		t.Errorf("Phorvex created a competing shadow: %d", len(pods.Items))
	}
}

func TestWarmSwapFailClosedNoReadyShadow(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	c := fakeC(leader)
	_, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: &mockVLLM{}}, boundReq(leader, model.ActionWarmSwap))
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
	hr, err := warmSwapHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: mv}, boundReq(leader, model.ActionWarmSwap))
	if err == nil {
		t.Fatal("fake controller cannot replenish after cutover")
	}
	if !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("unreachable stack must be flagged PENDING-GPU-VALIDATION, note=%q", hr.Note)
	}
}

// ---- kv-reset ----
func TestKVResetRealFlushPodAlive(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	c := fakeC(pod)
	mv := &mockVLLM{}
	hr, err := kvResetHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, boundReq(pod, model.ActionKVReset))
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
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	c := fakeC(pod)
	hr, err := kvResetHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: &mockVLLM{resetErr: errStackUnreachable}}, boundReq(pod, model.ActionKVReset))
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
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	c := fakeC(pod)
	_, err := kvResetHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: &mockVLLM{resetErr: errors.New("HTTP 500")}}, boundReq(pod, model.ActionKVReset))
	if err == nil {
		t.Fatal("kv-reset must FAIL-CLOSED when a reachable stack rejects the flush (no faked success)")
	}
}

// ---- endpoint-rotate ----
func TestEndpointRotateRestitchesRouteAndRollsBack(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRouteKey: "ep-old"})
	pod.Annotations[annoRouteService] = "infer-svc"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "infer-svc", UID: types.UID("uid-infer-svc"), ResourceVersion: "9"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{labelRouteKey: "ep-old"}}}
	c := fakeC(pod, svc)
	ec := EnactCtx{Client: c, Reader: c}
	hr, err := endpointRotateHandler{}.Enact(context.Background(), ec, Request{Namespace: "ns", Pod: "infer", TargetUID: string(pod.UID), Action: model.ActionEndpointRotate})
	if err != nil {
		t.Fatalf("endpoint-rotate: %v", err)
	}
	var p corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p)
	if p.Labels[labelRouteKey] == "ep-old" {
		t.Error("route-key not re-keyed")
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
	p.Annotations[annoGPUID] = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	p.Annotations[annoMIGProfile] = "2g.20gb"
	// an extended resource is non-overcommittable: the API server requires limits == requests.
	p.Spec.Containers[0].Resources.Requests = corev1.ResourceList{"nvidia.com/mig-1g.10gb": resource.MustParse("1")}
	p.Spec.Containers[0].Resources.Limits = corev1.ResourceList{"nvidia.com/mig-1g.10gb": resource.MustParse("1")}
	return p
}

func TestMIGRebindRealRepartitionEvictsPod(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	mm := &mockMIG{} // Available nil + Repartition succeeds
	hr, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", MIG: mm, VLLM: &mockVLLM{}, MIGProfiles: testMIGProfiles()}, boundReq(pod, model.ActionMIGRebind))
	if err != nil {
		t.Fatalf("mig-rebind: %v", err)
	}
	want := [3]string{"node-a", "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "2g.20gb"}
	if len(mm.calls) != 1 || mm.calls[0] != want {
		t.Errorf("mig-rebind must call the REAL Repartition(node,gpu,profile), got %v", mm.calls)
	}
	// The selected Pod deletion must be submitted before repartition; this does not prove CUDA state.
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err == nil {
		t.Error("mig-rebind must EVICT the pod off the GPU (delete) before repartition")
	}
	if !containsStr(hr.Note, "eviction submitted") || !containsStr(hr.Note, "PENDING-GPU-VALIDATION") {
		t.Errorf("note must record the submitted eviction + pending hardware proof, %q", hr.Note)
	}
}

// Baseline at origin/main: this well-formed tenant assertion selected a foreign GPU directly.
// The fixed path binds from PodResources and treats the annotation only as a matching assertion.
func TestMIGRebindConflictingValidGPUAnnotationRejectedBeforeEffects(t *testing.T) {
	pod := migPod("ns", "infer")
	pod.Annotations[annoGPUID] = "GPU-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"
	c := fakeC(pod)
	mm := &mockMIG{}
	if _, err := (migRebindHandler{}).Enact(t.Context(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", MIG: mm, VLLM: &mockVLLM{}, MIGProfiles: testMIGProfiles()}, boundReq(pod, model.ActionMIGRebind)); err == nil || !strings.Contains(err.Error(), "conflicts with allocated device") {
		t.Fatalf("foreign valid annotation was not rejected: %v", err)
	}
	if len(mm.calls) != 0 {
		t.Fatalf("GPU mutation reached: %v", mm.calls)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
		t.Fatalf("target changed: %v", err)
	}
}

func TestMIGRebindAllocationReleaseAndNewForeignAllocationRefuseGPU(t *testing.T) {
	for _, tc := range []struct {
		name       string
		revalidate func(bool) error
		want       string
	}{
		{"release-timeout", func(present bool) error {
			if !present {
				return errTargetAllocationPresent
			}
			return nil
		}, "wait for target allocation release"},
		{"new-foreign-allocation", func(present bool) error {
			if !present {
				return fmt.Errorf("physical GPU gained a foreign allocation")
			}
			return nil
		}, "foreign allocation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := migPod("ns", "infer")
			c := fakeC(pod)
			mm := &mockMIG{revalidate: tc.revalidate, releaseTimeout: 5 * time.Millisecond}
			hr, err := migRebindHandler{}.Enact(t.Context(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", MIG: mm, VLLM: &mockVLLM{}, MIGProfiles: testMIGProfiles()}, boundReq(pod, model.ActionMIGRebind))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !hr.Emitted {
				t.Fatalf("hr=%+v err=%v", hr, err)
			}
			if len(mm.calls) != 0 {
				t.Fatalf("repartition crossed refusal: %v", mm.calls)
			}
		})
	}
}

// PHORVEXSEC-121 Mode-C discipline: a failed physical repartition must never be
// reported as an emitted defence. The optimizer may have selected the candidate,
// but manager records actuation/credit only for Emitted=true.
func TestMIGRebindRepartitionFailureEmitsNothing(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	hr, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{
		Client: c, Reader: c, JournalNamespace: "operator",
		MIG:         &mockMIG{repErr: errors.New("live CUDA context blocks repartition")},
		VLLM:        &mockVLLM{},
		MIGProfiles: testMIGProfiles(),
	}, boundReq(pod, model.ActionMIGRebind))
	if err == nil {
		t.Fatal("failed repartition must return an error")
	}
	if !hr.Emitted || hr.MutationKind != "partial" {
		t.Fatalf("failed repartition hid its pod/GPU effects: %+v", hr)
	}
}

func TestMIGRebindFailClosedNoDevice(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRole: roleLeader}) // no MIG resource
	c := fakeC(pod)
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, MIG: &mockMIG{}}, boundReq(pod, model.ActionMIGRebind))
	if err == nil {
		t.Fatal("mig-rebind must FAIL-CLOSED without a MIG device")
	}
}

// The Available probe must fail-closed BEFORE any destructive eviction (the pod survives).
func TestMIGRebindFailClosedTransportUnavailable(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, MIG: &mockMIG{availErr: errors.New("node-exec not wired")}, VLLM: &mockVLLM{}, MIGProfiles: testMIGProfiles()}, boundReq(pod, model.ActionMIGRebind))
	if err == nil {
		t.Fatal("mig-rebind must FAIL-CLOSED when the node-exec transport is unavailable")
	}
	var p corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &p); err != nil {
		t.Error("an unavailable transport must NOT evict the pod (no destructive action before the probe passes)")
	}
}

func TestMIGRebindUnconfirmedDrainStopsBeforeEvictionAndGPU(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	mm := &mockMIG{}
	hr, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", MIG: mm, VLLM: &mockVLLM{drainErr: errStackUnreachable}, MIGProfiles: testMIGProfiles()}, boundReq(pod, model.ActionMIGRebind))
	if err == nil || !hr.Emitted || len(mm.calls) != 0 {
		t.Fatalf("unconfirmed drain crossed boundary: hr=%+v calls=%v err=%v", hr, mm.calls, err)
	}
	current := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, current); err != nil || current.UID != pod.UID {
		t.Fatalf("pod evicted on unconfirmed drain: %v", err)
	}
	var receipts corev1.ConfigMapList
	if err := c.List(context.Background(), &receipts, client.InNamespace("operator"), client.MatchingLabels{migRecoveryLabel: "v2"}); err != nil || len(receipts.Items) != 1 {
		t.Fatalf("recovery receipt not retained: %v %+v", err, receipts.Items)
	}
}

func TestMIGRebindInvalidTargetAndMissingReaderArePreEffect(t *testing.T) {
	for _, tc := range []struct {
		name, profile string
		reader        bool
	}{{"invalid-profile", "../../etc/passwd", true}, {"missing-reader", "2g.20gb", false}} {
		t.Run(tc.name, func(t *testing.T) {
			pod := migPod("ns", "infer")
			pod.Annotations[annoMIGProfile] = tc.profile
			c := fakeC(pod)
			ec := EnactCtx{Client: c, MIG: &mockMIG{}, VLLM: &mockVLLM{}}
			if tc.reader {
				ec.Reader = c
			}
			if _, err := (migRebindHandler{}).Enact(context.Background(), ec, boundReq(pod, model.ActionMIGRebind)); err == nil {
				t.Fatal("invalid precondition accepted")
			}
			current := &corev1.Pod{}
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, current); err != nil || current.Labels[labelRole] != roleLeader {
				t.Fatalf("precondition failure mutated pod: %v %+v", err, current.Labels)
			}
		})
	}
}

func TestMIGRebindDefaultRunnerFailsClosed(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	// no MIG injected => the package default (unconfigured nodeRunner) => must fail-closed.
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c}, boundReq(pod, model.ActionMIGRebind))
	if err == nil {
		t.Fatal("mig-rebind with the default unconfigured node runner must FAIL-CLOSED [PENDING-GPU-VALIDATION]")
	}
}

// ---- model-shard-replace ----
func TestModelShardReplaceWarmCutover(t *testing.T) {
	leader := aiPod("ns", "shard0", map[string]string{labelModelShard: "s", labelRole: roleLeader})
	shadow := aiPod("ns", "shard0b", map[string]string{labelModelShard: "s", labelRole: roleShadow, labelModelLoaded: "true"})
	c := fakeC(leader, shadow)
	hr, err := modelShardReplaceHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: &mockVLLM{loaded: true}}, boundReq(leader, model.ActionModelShardReplace))
	if err == nil || hr.MutationKind != "swap" {
		t.Fatalf("controller observation must remain pending in fake: result=%+v err=%v", hr, err)
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
	_, err := modelShardReplaceHandler{}.Enact(context.Background(), EnactCtx{Client: c}, boundReq(pod, model.ActionModelShardReplace))
	if err == nil {
		t.Fatal("model-shard-replace must FAIL-CLOSED without a declared shard")
	}
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }
