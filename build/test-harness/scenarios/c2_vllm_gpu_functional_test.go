package scenarios

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/gpufunctional"
)

type gpuFixtureGuard struct{}

func (gpuFixtureGuard) AssertMutationAllowed(string) error { return nil }

type gpuFixtureLog struct{}

func (*gpuFixtureLog) Logf(string, ...any) {}
func (*gpuFixtureLog) Command(string)      {}
func (*gpuFixtureLog) Commands() []string  { return nil }
func (*gpuFixtureLog) RawLogPath() string  { return "" }

func gpuFixtureObjects(t *testing.T) (*core.Env, *config.GPUFunctionalFixtureConfig, []runtime.Object) {
	t.Helper()
	started := metav1.NewTime(time.Date(2026, 9, 22, 1, 2, 3, 123456789, time.UTC))
	controller, ready := true, true
	defaultTolerationSeconds := int64(300)
	fixture := &config.GPUFunctionalFixtureConfig{
		Operation: "prefix-cache-reset", Mode: "direct", NamespaceUID: "00000000-0000-4000-8000-000000000001", RunLabel: "gpu-r1",
		NodeName: "gpu-node", NodeUID: "00000000-0000-4000-8000-000000000002", PodName: "vllm-0", PodUID: "00000000-0000-4000-8000-000000000003",
		OwnerKind: "StatefulSet", OwnerName: "vllm", OwnerUID: "00000000-0000-4000-8000-000000000004", ServiceName: "vllm", ServiceUID: "00000000-0000-4000-8000-000000000005",
		ContainerName: "vllm", Image: "registry.example/vllm@sha256:" + strings.Repeat("a", 64), ImageID: "containerd://sha256:" + strings.Repeat("b", 64), StartedAt: started.UTC().Format(time.RFC3339Nano),
		Port: 8000, Model: "facebook/opt-125m", ModelDigest: "sha256:" + strings.Repeat("c", 64), EngineSourceSHA256: strings.Repeat("d", 64), BearerTokenFile: "/private/token",
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: types.UID(fixture.NamespaceUID)}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: fixture.NodeName, UID: types.UID(fixture.NodeUID)}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: "nvidia.com/gpu", Value: "true", Effect: corev1.TaintEffectNoSchedule}}}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("8")}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	owner := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: fixture.OwnerName, Namespace: "sandbox", UID: types.UID(fixture.OwnerUID), Labels: map[string]string{vllmRunLabelKey: fixture.RunLabel}}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: fixture.PodName, Namespace: "sandbox", UID: types.UID(fixture.PodUID), Labels: map[string]string{vllmRunLabelKey: fixture.RunLabel, "app": "vllm"}, Annotations: map[string]string{vllmModelLabelKey: fixture.ModelDigest}, OwnerReferences: []metav1.OwnerReference{{Kind: fixture.OwnerKind, Name: fixture.OwnerName, UID: types.UID(fixture.OwnerUID), Controller: &controller}}},
		Spec: corev1.PodSpec{NodeName: fixture.NodeName, Tolerations: []corev1.Toleration{
			{Key: "nvidia.com/gpu", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule},
			{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &defaultTolerationSeconds},
			{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &defaultTolerationSeconds},
			{Key: "nvidia.com/gpu", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		}, Containers: []corev1.Container{{Name: fixture.ContainerName, Image: fixture.Image, Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: fixture.ContainerName, Image: fixture.Image, ImageID: fixture.ImageID, Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: started}}}}},
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: fixture.ServiceName, Namespace: "sandbox", UID: types.UID(fixture.ServiceUID), Labels: map[string]string{vllmRunLabelKey: fixture.RunLabel}}, Spec: corev1.ServiceSpec{Selector: map[string]string{vllmRunLabelKey: fixture.RunLabel, "app": "vllm"}, Ports: []corev1.ServicePort{{Port: 8000, TargetPort: intstr.FromInt(8000)}}}}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "vllm-1", Namespace: "sandbox", Labels: map[string]string{discoveryv1.LabelServiceName: fixture.ServiceName}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: fixture.PodName, UID: types.UID(fixture.PodUID)}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}}}
	objects := []runtime.Object{ns, node, owner, pod, svc, slice}
	kube := k8sfake.NewSimpleClientset(objects...)
	env := &core.Env{Kube: kube, Config: config.TargetConfig{Namespace: "sandbox", ExpectedNamespaceUID: fixture.NamespaceUID, GPUFunctionalFixture: fixture}, Guard: gpuFixtureGuard{}, Log: &gpuFixtureLog{}}
	if err := env.EnsureNamespace(t.Context()); err != nil {
		t.Fatal(err)
	}
	return env, fixture, objects
}

func TestVLLMGPUFunctionalMetadataAndRegistration(t *testing.T) {
	seen := map[string]core.ScenarioMeta{}
	for _, scenario := range core.Scenarios() {
		m := scenario.Metadata()
		seen[m.Name] = m
	}
	for _, name := range []string{vllmPrefixScenario, vllmDrainScenario} {
		m, ok := seen[name]
		if !ok {
			t.Fatalf("scenario %s not registered", name)
		}
		if !m.BenignControl || m.EffectiveRealism() != core.RealismExecutable || len(m.AttackTechniqueIDs) != 0 || len(m.ExercisedTechniqueIDs) != 0 || len(m.CapabilityRequirements) != 1 || m.CapabilityRequirements[0] != core.CapGPU || !strings.Contains(m.ClaimLimits, "no cross-session leak") {
			t.Fatalf("metadata %s=%+v", name, m)
		}
	}
}

func TestVLLMGPUFixtureExactIdentityBoundary(t *testing.T) {
	env, fixture, _ := gpuFixtureObjects(t)
	scenario := &c2VLLMFunctional{operation: "prefix-cache-reset"}
	if err := scenario.validateFixture(t.Context(), env, fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod, *corev1.Service)
		want   string
	}{
		{"pod replacement", func(p *corev1.Pod, _ *corev1.Service) { p.UID = "replacement" }, "Pod UID"},
		{"generic cleanup label", func(p *corev1.Pod, _ *corev1.Service) { p.Labels[core.OwnedLabelKey] = core.OwnedLabelValue }, "cleanup ownership"},
		{"service route drift", func(_ *corev1.Pod, s *corev1.Service) { s.Spec.Selector["app"] = "other" }, "selector does not select"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caseEnv, caseFixture, _ := gpuFixtureObjects(t)
			kube := caseEnv.Kube.(*k8sfake.Clientset)
			pod, _ := kube.CoreV1().Pods("sandbox").Get(context.Background(), caseFixture.PodName, metav1.GetOptions{})
			svc, _ := kube.CoreV1().Services("sandbox").Get(context.Background(), caseFixture.ServiceName, metav1.GetOptions{})
			tc.mutate(pod, svc)
			_, _ = kube.CoreV1().Pods("sandbox").Update(context.Background(), pod, metav1.UpdateOptions{})
			_, _ = kube.CoreV1().Services("sandbox").Update(context.Background(), svc, metav1.UpdateOptions{})
			if err := scenario.validateFixture(t.Context(), caseEnv, caseFixture); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal("fixture drift accepted")
			}
		})
	}
}

func TestVLLMGPUNodeAcceptsRetainedDedicatedTaintShapeAndRejectsDrift(t *testing.T) {
	env, fixture, _ := gpuFixtureObjects(t)
	scenario := &c2VLLMFunctional{operation: "prefix-cache-reset"}
	if err := scenario.validateFixture(t.Context(), env, fixture); err != nil {
		t.Fatalf("retained dedicated GPU node/Pod shape rejected: %v", err)
	}
	if err := scenario.Teardown(t.Context(), env); err != nil {
		t.Fatalf("teardown rejected unchanged retained GPU node/Pod shape: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Node, *corev1.Pod)
	}{
		{"unschedulable", func(n *corev1.Node, _ *corev1.Pod) { n.Spec.Unschedulable = true }},
		{"not ready", func(n *corev1.Node, _ *corev1.Pod) { n.Status.Conditions[0].Status = corev1.ConditionFalse }},
		{"insufficient GPU", func(n *corev1.Node, _ *corev1.Pod) { n.Status.Allocatable["nvidia.com/gpu"] = resource.MustParse("0") }},
		{"foreign taint", func(n *corev1.Node, _ *corev1.Pod) {
			n.Spec.Taints = []corev1.Taint{{Key: "foreign", Effect: corev1.TaintEffectNoSchedule}}
		}},
		{"additional taint", func(n *corev1.Node, _ *corev1.Pod) {
			n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: "foreign", Effect: corev1.TaintEffectNoSchedule})
		}},
		{"missing toleration", func(_ *corev1.Node, p *corev1.Pod) { p.Spec.Tolerations = nil }},
		{"wrong toleration value", func(_ *corev1.Node, p *corev1.Pod) { p.Spec.Tolerations[0].Value = "false" }},
		{"broad exists toleration", func(_ *corev1.Node, p *corev1.Pod) {
			p.Spec.Tolerations[0] = corev1.Toleration{Key: "nvidia.com/gpu", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caseEnv, caseFixture, _ := gpuFixtureObjects(t)
			kube := caseEnv.Kube.(*k8sfake.Clientset)
			node, _ := kube.CoreV1().Nodes().Get(t.Context(), caseFixture.NodeName, metav1.GetOptions{})
			pod, _ := kube.CoreV1().Pods("sandbox").Get(t.Context(), caseFixture.PodName, metav1.GetOptions{})
			tc.mutate(node, pod)
			_, _ = kube.CoreV1().Nodes().Update(t.Context(), node, metav1.UpdateOptions{})
			_, _ = kube.CoreV1().Pods("sandbox").Update(t.Context(), pod, metav1.UpdateOptions{})
			if err := scenario.validateFixture(t.Context(), caseEnv, caseFixture); err == nil {
				t.Fatal("GPU node/toleration drift accepted during setup validation")
			}
			if err := scenario.Teardown(t.Context(), caseEnv); err == nil {
				t.Fatal("GPU node/toleration drift accepted during teardown validation")
			}
		})
	}
}

func TestVLLMGPUNodeWithoutTaintsRemainsEligible(t *testing.T) {
	env, fixture, _ := gpuFixtureObjects(t)
	kube := env.Kube.(*k8sfake.Clientset)
	node, _ := kube.CoreV1().Nodes().Get(t.Context(), fixture.NodeName, metav1.GetOptions{})
	pod, _ := kube.CoreV1().Pods("sandbox").Get(t.Context(), fixture.PodName, metav1.GetOptions{})
	node.Spec.Taints, pod.Spec.Tolerations = nil, nil
	_, _ = kube.CoreV1().Nodes().Update(t.Context(), node, metav1.UpdateOptions{})
	_, _ = kube.CoreV1().Pods("sandbox").Update(t.Context(), pod, metav1.UpdateOptions{})
	if err := (&c2VLLMFunctional{operation: "prefix-cache-reset"}).validateFixture(t.Context(), env, fixture); err != nil {
		t.Fatalf("untainted eligible GPU node rejected: %v", err)
	}
}

func TestVLLMGPUPostReopenReadinessConvergesOnlyForSameAuthority(t *testing.T) {
	env, fixture, _ := gpuFixtureObjects(t)
	kube := env.Kube.(*k8sfake.Clientset)
	pod, _ := kube.CoreV1().Pods("sandbox").Get(t.Context(), fixture.PodName, metav1.GetOptions{})
	pod.Status.Conditions[0].Status = corev1.ConditionFalse
	_, _ = kube.CoreV1().Pods("sandbox").Update(t.Context(), pod, metav1.UpdateOptions{})
	slice, _ := kube.DiscoveryV1().EndpointSlices("sandbox").Get(t.Context(), "vllm-1", metav1.GetOptions{})
	ready := false
	slice.Endpoints[0].Conditions.Ready = &ready
	_, _ = kube.DiscoveryV1().EndpointSlices("sandbox").Update(t.Context(), slice, metav1.UpdateOptions{})

	scenario := &c2VLLMFunctional{operation: "request-drain"}
	go func() {
		time.Sleep(5 * time.Millisecond)
		pod, _ := kube.CoreV1().Pods("sandbox").Get(context.Background(), fixture.PodName, metav1.GetOptions{})
		pod.Status.Conditions[0].Status = corev1.ConditionTrue
		_, _ = kube.CoreV1().Pods("sandbox").Update(context.Background(), pod, metav1.UpdateOptions{})
		slice, _ := kube.DiscoveryV1().EndpointSlices("sandbox").Get(context.Background(), "vllm-1", metav1.GetOptions{})
		ready := true
		slice.Endpoints[0].Conditions.Ready = &ready
		_, _ = kube.DiscoveryV1().EndpointSlices("sandbox").Update(context.Background(), slice, metav1.UpdateOptions{})
	}()
	if err := scenario.waitFixtureReady(t.Context(), env, fixture, 200*time.Millisecond, time.Millisecond); err != nil {
		t.Fatalf("same-authority readiness did not converge: %v", err)
	}

	env, fixture, _ = gpuFixtureObjects(t)
	kube = env.Kube.(*k8sfake.Clientset)
	pod, _ = kube.CoreV1().Pods("sandbox").Get(t.Context(), fixture.PodName, metav1.GetOptions{})
	pod.Status.ContainerStatuses[0].RestartCount++
	_, _ = kube.CoreV1().Pods("sandbox").Update(t.Context(), pod, metav1.UpdateOptions{})
	err := scenario.waitFixtureReady(t.Context(), env, fixture, 200*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "restart count") {
		t.Fatalf("container identity drift was not rejected immediately: %v", err)
	}

	env, fixture, _ = gpuFixtureObjects(t)
	kube = env.Kube.(*k8sfake.Clientset)
	slice, _ = kube.DiscoveryV1().EndpointSlices("sandbox").Get(t.Context(), "vllm-1", metav1.GetOptions{})
	slice.Endpoints[0].TargetRef.UID = "foreign"
	_, _ = kube.DiscoveryV1().EndpointSlices("sandbox").Update(t.Context(), slice, metav1.UpdateOptions{})
	err = scenario.waitFixtureReady(t.Context(), env, fixture, 200*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "EndpointSlice target identity") {
		t.Fatalf("foreign endpoint target was not rejected immediately: %v", err)
	}
}

func TestVLLMGPUTeardownDoesNotRetryAuthorityDriftAfterReopen(t *testing.T) {
	env, fixture, _ := gpuFixtureObjects(t)
	kube := env.Kube.(*k8sfake.Clientset)
	podGets := 0
	kube.Fake.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		podGets++
		if podGets != 1 {
			return false, nil, nil
		}
		pod, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("pods"), "sandbox", fixture.PodName)
		if err != nil {
			return true, nil, err
		}
		drifted := pod.(*corev1.Pod).DeepCopy()
		drifted.UID = types.UID("00000000-0000-4000-8000-000000000099")
		return true, drifted, nil
	})
	reopen := &gpufunctional.DrainOperation{State: "OPENED", Admission: "OPEN"}
	observation := &gpufunctional.Observation{Status: 200}
	scenario := &c2VLLMFunctional{operation: "request-drain", receipt: gpufunctional.DrainReceipt{
		Reopen: reopen, ReopenObservation: observation,
	}}
	err := scenario.Teardown(t.Context(), env)
	if err == nil || !strings.Contains(err.Error(), "Pod UID differs") {
		t.Fatalf("teardown did not retain the first authority drift: %v", err)
	}
	if podGets != 1 {
		t.Fatalf("authority drift triggered %d Pod reads; want exactly the first validation read", podGets)
	}
}

func TestVLLMCapabilityBindsSourceAndCurrentPod(t *testing.T) {
	fixture := &config.GPUFunctionalFixtureConfig{PodUID: "pod", EngineSourceSHA256: strings.Repeat("a", 64), ProxySourceGitSHA: strings.Repeat("b", 40)}
	good := gpufunctional.Capability{PodUID: "pod", EngineSource: strings.Repeat("a", 64), ProxySource: strings.Repeat("b", 40), Admission: "OPEN"}
	if err := validateGPUCapability(good, fixture); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.EngineSource = strings.Repeat("c", 64)
	if err := validateGPUCapability(bad, fixture); err == nil {
		t.Fatal("wrong source accepted")
	}
}

func TestVLLMProtocolCountsComeOnlyFromObservedProducerCalls(t *testing.T) {
	if a, ack, r, rack := vllmProtocolCounts(gpufunctional.PrefixReceipt{}); a != 0 || ack != 0 || r != 0 || rack != 0 {
		t.Fatalf("empty direct receipt fabricated counts: %d %d %d %d", a, ack, r, rack)
	}
	prefix := gpufunctional.PrefixReceipt{
		Reset: &gpufunctional.Reset{Observation: gpufunctional.Observation{StartedAt: "started", Status: 200, Body: `{"success":true}`}},
		Busy:  &gpufunctional.BusyReceipt{Reset: gpufunctional.Reset{Observation: gpufunctional.Observation{StartedAt: "started", Status: 0}}},
	}
	if a, ack, r, rack := vllmProtocolCounts(prefix); a != 2 || ack != 1 || r != 0 || rack != 0 {
		t.Fatalf("prefix counts differ: %d %d %d %d", a, ack, r, rack)
	}
	drain := gpufunctional.DrainReceipt{
		Create:            &gpufunctional.DrainOperation{OperationID: "operation"},
		CreateObservation: &gpufunctional.Observation{StartedAt: "started", Status: 201, Body: `{}`},
		Reopen:            &gpufunctional.DrainOperation{State: "OPENED"},
		CleanupObservations: []gpufunctional.Observation{
			{Path: "/v1/drain/operations/1/id?observation_nonce=n", StartedAt: "started", Status: 200, Body: `{}`},
			{Path: "/v1/drain/operations/1/id/reopen", StartedAt: "started", Status: 200, Body: `{}`},
		},
	}
	if a, ack, r, rack := vllmProtocolCounts(drain); a != 1 || ack != 1 || r != 1 || rack != 1 {
		t.Fatalf("drain counts differ: %d %d %d %d", a, ack, r, rack)
	}
}

func TestVLLMPortForwardCleanupReportsSurvivingTransport(t *testing.T) {
	stop := make(chan struct{})
	scenario := &c2VLLMFunctional{portStop: stop, portDone: make(chan error)}
	if err := scenario.closePortForwardWithin(time.Millisecond); err == nil {
		t.Fatal("port-forward cleanup timeout was hidden")
	}
	select {
	case <-stop:
	default:
		t.Fatal("port-forward stop authority was not closed")
	}
}
