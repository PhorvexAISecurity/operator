package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// TestCleanupOwnedActualAPIPreservesExternalFixture exercises the cleanup
// producer against a real local API server. The unit tests deliberately retain
// fake-client controls for individual failure paths, but a fake DeleteCollection
// does not implement API-server selector/deletion behavior and cannot prove this
// ownership boundary.
func TestCleanupOwnedActualAPIPreservesExternalFixture(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Skip("KUBEBUILDER_ASSETS is required for the isolated API control")
	}
	if !filepath.IsAbs(assets) {
		t.Fatal("KUBEBUILDER_ASSETS must be an absolute source-bound directory")
	}
	localOnly := false
	testAPI := &envtest.Environment{UseExistingCluster: &localOnly, BinaryAssetsDirectory: assets}
	restCfg, err := testAPI.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := testAPI.Stop(); err != nil {
			t.Error(err)
		}
	})
	kube, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatal(err)
	}

	const ns = "checkpoint-cleanup-actual-api"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		zero := int64(0)
		_ = kube.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	})

	owned := map[string]string{OwnedLabelKey: OwnedLabelValue}
	container := corev1.Container{Name: "fixture", Image: "registry.k8s.io/pause:3.10"}
	external := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "checkpoint-local-holder", Namespace: ns, Labels: map[string]string{"fixture.phorvex.ai/external-owner": "checkpoint-local-holder"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}
	if _, err := kube.CoreV1().Pods(ns).Create(ctx, external, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-config", Namespace: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "owned-pod", Namespace: ns, Labels: owned}, Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	selector := map[string]string{"app": "owned"}
	if _, err := kube.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "owned-deployment", Namespace: ns, Labels: owned}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: selector}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: selector}, Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.AppsV1().ReplicaSets(ns).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "owned-replicaset", Namespace: ns, Labels: owned}, Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: selector}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: selector}, Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Services(ns).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "owned-service", Namespace: ns, Labels: owned}, Spec: corev1.ServiceSpec{Selector: selector, Ports: []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt(8080)}}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	emptyClass := ""
	createdPVC, err := kube.CoreV1().PersistentVolumeClaims(ns).Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "owned-pvc", Namespace: ns, Labels: owned}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &emptyClass, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// envtest intentionally runs no kube-controller-manager. The API admission
	// plugin may attach pvc-protection, but no local controller exists to remove
	// it after all consumers are gone. Remove that controller-owned finalizer in
	// the fixture so this test measures the cleanup producer and API selector
	// behavior rather than claiming an absent controller timed out correctly.
	if len(createdPVC.Finalizers) != 0 {
		createdPVC = createdPVC.DeepCopy()
		createdPVC.Finalizers = nil
		if _, err := kube.CoreV1().PersistentVolumeClaims(ns).Update(ctx, createdPVC, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := kube.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owned-config", Namespace: ns, Labels: owned}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "owned-secret", Namespace: ns, Labels: owned}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "owned-account", Namespace: ns, Labels: owned}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.RbacV1().Roles(ns).Create(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "owned-role", Namespace: ns, Labels: owned}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.RbacV1().RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "owned-binding", Namespace: ns, Labels: owned}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "owned-role"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	env := &Env{Kube: kube, Rest: restCfg, Config: config.TargetConfig{Namespace: ns, Context: "envtest", OwnedAck: true}, Log: &nopLogger{}, Guard: refusingGuard{allow: ns}}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cleanupCancel()
	if err := env.CleanupOwned(cleanupCtx, false); err != nil {
		t.Fatalf("actual API cleanup failed: %v", err)
	}
	// A second pass proves the exact producer is idempotent after absence.
	if err := env.CleanupOwned(cleanupCtx, false); err != nil {
		t.Fatalf("idempotent actual API cleanup failed: %v", err)
	}
	if _, err := kube.CoreV1().Pods(ns).Get(ctx, external.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("external holder was removed: %v", err)
	}
	if _, err := kube.CoreV1().ConfigMaps(ns).Get(ctx, "foreign-config", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign object was removed: %v", err)
	}
	if _, err := kube.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		t.Fatalf("namespace was removed by preserve-mode cleanup: %v", err)
	}

	assertEmpty := func(kind string, length int, err error) {
		t.Helper()
		if err != nil || length != 0 {
			t.Fatalf("owned %s after cleanup: count=%d err=%v", kind, length, err)
		}
	}
	lo := metav1.ListOptions{LabelSelector: OwnedSelector()}
	pods, err := kube.CoreV1().Pods(ns).List(ctx, lo)
	assertEmpty("pods", len(pods.Items), err)
	deps, err := kube.AppsV1().Deployments(ns).List(ctx, lo)
	assertEmpty("deployments", len(deps.Items), err)
	rss, err := kube.AppsV1().ReplicaSets(ns).List(ctx, lo)
	assertEmpty("replicasets", len(rss.Items), err)
	svcs, err := kube.CoreV1().Services(ns).List(ctx, lo)
	assertEmpty("services", len(svcs.Items), err)
	pvcs, err := kube.CoreV1().PersistentVolumeClaims(ns).List(ctx, lo)
	assertEmpty("persistentvolumeclaims", len(pvcs.Items), err)
	cms, err := kube.CoreV1().ConfigMaps(ns).List(ctx, lo)
	assertEmpty("configmaps", len(cms.Items), err)
	secrets, err := kube.CoreV1().Secrets(ns).List(ctx, lo)
	assertEmpty("secrets", len(secrets.Items), err)
	accounts, err := kube.CoreV1().ServiceAccounts(ns).List(ctx, lo)
	assertEmpty("serviceaccounts", len(accounts.Items), err)
	bindings, err := kube.RbacV1().RoleBindings(ns).List(ctx, lo)
	assertEmpty("rolebindings", len(bindings.Items), err)
	roles, err := kube.RbacV1().Roles(ns).List(ctx, lo)
	assertEmpty("roles", len(roles.Items), err)

	if _, err := kube.CoreV1().PersistentVolumeClaims(ns).Get(ctx, "owned-pvc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned PVC absence was not observed: %v", err)
	}
}
