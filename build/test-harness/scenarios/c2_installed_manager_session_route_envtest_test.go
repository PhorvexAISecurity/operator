package scenarios

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type statusConflictKube struct {
	kubernetes.Interface
	writer kubernetes.Interface
	fired  atomic.Bool
}

func (k *statusConflictKube) CoreV1() typedcorev1.CoreV1Interface {
	return statusConflictCore{CoreV1Interface: k.Interface.CoreV1(), parent: k}
}

type statusConflictCore struct {
	typedcorev1.CoreV1Interface
	parent *statusConflictKube
}

func (c statusConflictCore) Pods(ns string) typedcorev1.PodInterface {
	return &statusConflictPods{PodInterface: c.CoreV1Interface.Pods(ns), namespace: ns, parent: c.parent}
}

type statusConflictPods struct {
	typedcorev1.PodInterface
	namespace string
	parent    *statusConflictKube
}

func (p *statusConflictPods) Update(ctx context.Context, pod *corev1.Pod, opts metav1.UpdateOptions) (*corev1.Pod, error) {
	if p.parent.fired.CompareAndSwap(false, true) {
		fresh, err := p.parent.writer.CoreV1().Pods(p.namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		fresh.Status.PodIP = "192.0.2.10"
		if _, err := p.parent.writer.CoreV1().Pods(p.namespace).UpdateStatus(ctx, fresh, metav1.UpdateOptions{}); err != nil {
			return nil, err
		}
	}
	return p.PodInterface.Update(ctx, pod, opts)
}

func TestInstalledSessionRouteBindActualAPIRecoversFromStatusResourceVersionConflict(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Skip("KUBEBUILDER_ASSETS is required for actual API conflict control")
	}
	if !filepath.IsAbs(assets) {
		t.Fatal("KUBEBUILDER_ASSETS must be absolute")
	}
	local := false
	api := &envtest.Environment{UseExistingCluster: &local, BinaryAssetsDirectory: assets}
	cfg, err := api.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = api.Stop() })
	writer, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ns, err := writer.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "installed-route-"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env := &core.Env{Kube: &statusConflictKube{Interface: reader, writer: writer}, Config: config.TargetConfig{Namespace: ns.Name}, ScenarioName: installedSessionScenario, DefenderName: "d-nomtd", Log: &dpLogger{}, Guard: dpGuard{}}
	labels := env.OwnedLabels(map[string]string{"app": installedSessionApp})
	one := int32(1)
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": installedSessionApp}}
	dep, err := writer.AppsV1().Deployments(ns.Name).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: installedSessionDeployment}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: selector, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": installedSessionApp}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	controller := true
	rs, err := writer.AppsV1().ReplicaSets(ns.Name).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "installed-rs", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Replicas: &one, Selector: selector, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": installedSessionApp}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}}}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	createPod := func(name string) *corev1.Pod {
		p, err := writer.CoreV1().Pods(ns.Name).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels, Annotations: map[string]string{"r6th.io/session-source-sha256": sessionServerSourceSHA256()}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "session", Image: sessionPythonImage, Command: []string{"python3", "-B", "-c", sessionServerSource}, Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: sessionPort}}}}}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		p, err = writer.CoreV1().Pods(ns.Name).UpdateStatus(ctx, p, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	target, peer := createPod("target"), createPod("peer")
	bound := env.Kube.(*statusConflictKube)
	got, err := bindInstalledSessionTargetRoute(ctx, env, target.Name, target.UID, peer.UID, dep.UID, "trial-0", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.fired.Load() || got.UID != target.UID || got.Labels[installedSessionTargetRoute] != "trial-0" {
		t.Fatalf("actual API conflict not recovered: fired=%v got=%+v", bound.fired.Load(), got)
	}
	if got.ResourceVersion == target.ResourceVersion {
		t.Fatal("actual API bind did not advance resourceVersion")
	}
}
