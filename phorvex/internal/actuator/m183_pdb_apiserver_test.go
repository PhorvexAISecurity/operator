package actuator

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m183ActualFixture struct {
	client client.Client
	policy *v1alpha1.PhorvexPolicy
	pods   []*corev1.Pod
}

func m183ActualObjects(t *testing.T, c client.Client, ns string, podCount int, allowed int32, withPDB bool) m183ActualFixture {
	t.Helper()
	ctx := t.Context()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	replicas := int32(podCount)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "voice"}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "voice"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "voice", Image: "unused:test"}}}}}}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	cap := int64(9)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "voice"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}},
		Budget:  v1alpha1.BudgetSpec{MaxGracePeriodSeconds: &cap, TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	yes := true
	pods := make([]*corev1.Pod, 0, podCount)
	for i := 0; i < podCount; i++ {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: fmt.Sprintf("voice-%d", i), Labels: map[string]string{"app": "voice"}, Finalizers: []string{"m183.test/hold"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &cap, Containers: []corev1.Container{{Name: "voice", Image: "unused:test"}}}}
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()}}
		if err := c.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pods = append(pods, pod)
	}
	if withPDB {
		minAvailable := intstr.FromInt(podCount - int(allowed))
		pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "voice"}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailable, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}}}}
		if err := c.Create(ctx, pdb); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pdb), pdb); err != nil {
			t.Fatal(err)
		}
		pdb.Status = policyv1.PodDisruptionBudgetStatus{ObservedGeneration: pdb.Generation, CurrentHealthy: int32(podCount), DesiredHealthy: int32(podCount) - allowed, ExpectedPods: int32(podCount), DisruptionsAllowed: allowed}
		if err := c.Status().Update(ctx, pdb); err != nil {
			t.Fatal(err)
		}
	}
	return m183ActualFixture{client: c, policy: policy, pods: pods}
}

func (f m183ActualFixture) request(pod *corev1.Pod) Request {
	return Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionRotate, PolicyName: f.policy.Name, PolicyUID: string(f.policy.UID), PolicyGeneration: f.policy.Generation, MaxGracePeriodSeconds: 9}
}

func TestM183ActualAPIServerPDBAdmissionAndConcurrency(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, policyv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("closed budget refuses without mutation", func(t *testing.T) {
		f := m183ActualObjects(t, c, "m183-closed", 1, 0, true)
		result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, f.request(f.pods[0]))
		if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, "pdb-eviction-admission-refused") {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		fresh := &corev1.Pod{}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(f.pods[0]), fresh); err != nil || fresh.DeletionTimestamp != nil {
			t.Fatalf("closed budget changed Pod: deletion=%v err=%v", fresh.DeletionTimestamp, err)
		}
	})

	t.Run("no PDB ordinary admission remains positive", func(t *testing.T) {
		f := m183ActualObjects(t, c, "m183-none", 1, 0, false)
		result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, f.request(f.pods[0]))
		if err != nil || !result.Emitted || result.GracefulTermination == nil || result.GracefulTermination.TerminationStatus != "unconfirmed" {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})

	t.Run("overlapping PDBs refuse without delete fallback", func(t *testing.T) {
		f := m183ActualObjects(t, c, "m183-overlap", 1, 1, true)
		minAvailable := intstr.FromInt(0)
		second := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: f.pods[0].Namespace, Name: "voice-second"}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailable, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}}}}
		if err := c.Create(t.Context(), second); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(second), second); err != nil {
			t.Fatal(err)
		}
		second.Status = policyv1.PodDisruptionBudgetStatus{ObservedGeneration: second.Generation, CurrentHealthy: 1, DesiredHealthy: 0, ExpectedPods: 1, DisruptionsAllowed: 1}
		if err := c.Status().Update(t.Context(), second); err != nil {
			t.Fatal(err)
		}
		result, err := dispatch(t.Context(), EnactCtx{Client: c, Reader: c}, f.request(f.pods[0]))
		if err == nil || result.Emitted {
			t.Fatalf("overlapping PDB result=%+v err=%v", result, err)
		}
		fresh := &corev1.Pod{}
		if getErr := c.Get(t.Context(), client.ObjectKeyFromObject(f.pods[0]), fresh); getErr != nil || fresh.DeletionTimestamp != nil {
			t.Fatalf("overlapping PDB fallback changed Pod: deletion=%v err=%v", fresh.DeletionTimestamp, getErr)
		}
	})

	t.Run("one available disruption admits at most one concurrent eviction", func(t *testing.T) {
		f := m183ActualObjects(t, c, "m183-concurrent", 2, 1, true)
		dispatchCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		type outcome struct {
			result Result
			err    error
		}
		start := make(chan struct{})
		out := make(chan outcome, 2)
		var wg sync.WaitGroup
		for _, pod := range f.pods {
			pod := pod
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				result, err := dispatch(dispatchCtx, EnactCtx{Client: c, Reader: c}, f.request(pod))
				out <- outcome{result: result, err: err}
			}()
		}
		close(start)
		wg.Wait()
		close(out)
		accepted, refused := 0, 0
		for got := range out {
			if got.err != nil {
				t.Fatalf("dispatch error: %v", got.err)
			}
			if got.result.Emitted {
				accepted++
			} else if got.result.NoEffect == NoEffectRefused && strings.Contains(got.result.Note, "pdb-eviction-admission-refused") {
				refused++
			} else {
				t.Fatalf("unexpected result: %+v", got.result)
			}
		}
		if accepted != 1 || refused != 1 {
			t.Fatalf("accepted=%d refused=%d", accepted, refused)
		}
	})
}
