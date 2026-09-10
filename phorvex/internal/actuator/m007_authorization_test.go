package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM007RestrictedRequests(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated API server")
	}
	env := &envtest.Environment{}
	env.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
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
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, networkingv1.AddToScheme, rbacv1.AddToScheme, authv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	create := func(obj client.Object) {
		t.Helper()
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
	}
	create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m007"}})
	roles := m007ReadRoles(t, "../../config/rbac/phorvex-actuator-role.yaml")
	role := roles[0].DeepCopy()
	role.Namespace = "m007"
	create(role)
	create(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "actuator", Namespace: "m007"}})
	create(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "routine", Namespace: "m007"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "actuator", Namespace: "m007"}}})
	user := "system:serviceaccount:m007:actuator"
	groups := []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:m007"}
	restricted := rest.CopyConfig(cfg)
	restricted.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
	c, err := client.New(restricted, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "fixture", Namespace: "m007"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "busybox"}}}}
	create(pod)
	// Wait for authorizer propagation using a justified positive operation.
	for {
		err = c.Get(ctx, client.ObjectKeyFromObject(pod), pod)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	pod.Labels = map[string]string{"m007": "updated"}
	if err := c.Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	persisted := &corev1.Pod{}
	if err := admin.Get(ctx, client.ObjectKeyFromObject(pod), persisted); err != nil || persisted.Labels["m007"] != "updated" {
		t.Fatalf("update not persisted: %v", err)
	}
	var nps networkingv1.NetworkPolicyList
	if err := c.List(ctx, &nps, client.InNamespace("m007")); err != nil {
		t.Fatal("GC list denied:", err)
	}
	// Sensitive negatives use authorization reviews, never real Secret reads/deletes.
	for _, a := range []authv1.ResourceAttributes{
		{Namespace: "m007", Verb: "patch", Resource: "pods"},
		{Namespace: "m007", Verb: "get", Resource: "secrets"},
		{Namespace: "m007", Verb: "delete", Resource: "serviceaccounts"},
		{Namespace: "m007", Verb: "update", Group: "discovery.k8s.io", Resource: "endpointslices"},
		{Namespace: "m007", Verb: "update", Resource: "pods", Subresource: "ephemeralcontainers"},
		{Namespace: "kube-system", Verb: "update", Resource: "pods"},
	} {
		review := &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{User: user, Groups: groups, ResourceAttributes: &a}}
		if err := admin.Create(ctx, review); err != nil {
			t.Fatal(err)
		}
		if review.Status.Allowed {
			t.Fatalf("unexpected grant: %+v", a)
		}
	}
	t.Log("restricted Pod GET/UPDATE persisted, NetworkPolicy LIST succeeded, six sensitive/cross-scope authorization negatives denied")
}
