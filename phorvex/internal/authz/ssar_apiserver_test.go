package authz

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestClusterScopedReviewRejectsNamespacedOnlyGrant(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated API server")
	}
	ctx := context.Background()
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
	admin, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m001"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.CoreV1().ServiceAccounts("m001").Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "manager"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	rule := rbacv1.PolicyRule{APIGroups: []string{"amtd.r6security.com"}, Resources: []string{"securityevents"}, Verbs: []string{"create"}}
	if _, err = admin.RbacV1().Roles("m001").Create(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "event-writer", Namespace: "m001"}, Rules: []rbacv1.PolicyRule{rule}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "manager", Namespace: "m001"}
	if _, err = admin.RbacV1().RoleBindings("m001").Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "event-writer", Namespace: "m001"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "event-writer"}, Subjects: []rbacv1.Subject{subject}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	impersonated := rest.CopyConfig(cfg)
	impersonated.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:m001:manager", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:m001", "system:authenticated"}}
	manager, err := kubernetes.NewForConfig(impersonated)
	if err != nil {
		t.Fatal(err)
	}
	verb := Verb{Group: "amtd.r6security.com", Resource: "securityevents", Verb: "create", ClusterScoped: true}
	review := func() (bool, bool, string) {
		return NewChecker(manager, time.Nanosecond).Allowed(ctx, "m001", []Verb{verb})
	}
	if err := wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, 5*time.Second, true, func(context.Context) (bool, error) {
		allowed, unknown, _ := review()
		return !allowed && !unknown, nil
	}); err != nil {
		t.Fatalf("namespaced grant unexpectedly satisfied cluster-scoped review: %v", err)
	}
	if _, err = admin.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "m001-event-writer"}, Rules: []rbacv1.PolicyRule{rule}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "m001-event-writer"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "m001-event-writer"}, Subjects: []rbacv1.Subject{subject}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(ctx, 10*time.Millisecond, 5*time.Second, true, func(context.Context) (bool, error) {
		allowed, unknown, _ := review()
		return allowed && !unknown, nil
	}); err != nil {
		t.Fatalf("cluster grant did not satisfy cluster-scoped review: %v", err)
	}
}
