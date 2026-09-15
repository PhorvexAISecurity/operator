package actuator

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestM004RenderedIdentityAuthorization installs only the actual Helm-rendered
// ServiceAccounts/RBAC into an isolated API server with RBAC authorization. No
// chart rule is replicated in the test; SubjectAccessReview evaluates the bound
// service-account identities and their real namespace-scoped plus cluster grants.
func TestM004RenderedIdentityAuthorization(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	rendered := renderChart(t,
		"phorvex.audit.enabled=true", "phorvex.console.enabled=true",
		"phorvex.console.auditTransport.serverSecretName=m004-server",
		"phorvex.console.auditTransport.clientSecretName=m004-client",
		"phorvex.console.auditTransport.serverDNSName=audit-source.test",
		"phorvex.console.auditTransport.clientDNSName=audit-console.test")
	localOnly := false
	env := &envtest.Environment{UseExistingCluster: &localOnly}
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
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme, authorizationv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(rendered)), 4096)
	var managerSA, consoleSA string
	var roles []client.Object
	var bindings []client.Object
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(doc) == 0 {
			continue
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		switch doc["kind"] {
		case "ServiceAccount":
			var sa corev1.ServiceAccount
			if err := json.Unmarshal(raw, &sa); err != nil {
				t.Fatal(err)
			}
			if sa.Namespace == "" {
				sa.Namespace = "default"
			}
			if strings.Contains(sa.Name, "console") {
				consoleSA = sa.Name
			} else {
				managerSA = sa.Name
			}
			if err := admin.Create(ctx, &sa); err != nil {
				t.Fatal(err)
			}
		case "ClusterRole":
			var role rbacv1.ClusterRole
			if err := json.Unmarshal(raw, &role); err != nil {
				t.Fatal(err)
			}
			roles = append(roles, &role)
		case "Role":
			var role rbacv1.Role
			if err := json.Unmarshal(raw, &role); err != nil {
				t.Fatal(err)
			}
			if role.Namespace == "" {
				role.Namespace = "default"
			}
			roles = append(roles, &role)
		case "ClusterRoleBinding":
			var binding rbacv1.ClusterRoleBinding
			if err := json.Unmarshal(raw, &binding); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, &binding)
		case "RoleBinding":
			var binding rbacv1.RoleBinding
			if err := json.Unmarshal(raw, &binding); err != nil {
				t.Fatal(err)
			}
			if binding.Namespace == "" {
				binding.Namespace = "default"
			}
			bindings = append(bindings, &binding)
		}
	}
	if managerSA == "" || consoleSA == "" || managerSA == consoleSA {
		t.Fatalf("rendered identities not distinct: manager=%q console=%q", managerSA, consoleSA)
	}
	for _, o := range roles {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range bindings {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	check := func(sa string, a authorizationv1.ResourceAttributes, want bool) {
		t.Helper()
		user := "system:serviceaccount:default:" + sa
		review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User: user, Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:default"}, ResourceAttributes: &a}}
		if err := admin.Create(ctx, review); err != nil {
			t.Fatal(err)
		}
		if review.Status.Allowed != want {
			t.Fatalf("%s %s/%s %s: allowed=%v want=%v reason=%s", user, a.Group, a.Resource, a.Verb, review.Status.Allowed, want, review.Status.Reason)
		}
	}
	// Positive authorizer propagation checks precede denied controls.
	for _, sa := range []string{managerSA, consoleSA} {
		deadline := time.Now().Add(10 * time.Second)
		for {
			a := authorizationv1.ResourceAttributes{Namespace: "default", Resource: "pods", Verb: "get"}
			user := "system:serviceaccount:default:" + sa
			review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user, Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:default"}, ResourceAttributes: &a}}
			if err := admin.Create(ctx, review); err != nil {
				t.Fatal(err)
			}
			if review.Status.Allowed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("authorizer did not observe %s binding: %s", sa, review.Status.Reason)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "pods", Verb: "get"}, true)
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "phorvex.ai", Resource: "phorvexpolicies", Subresource: "status", Verb: "update"}, true)
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "amtd.r6security.com", Resource: "securityevents", Verb: "create"}, true)
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "pods", Subresource: "log", Verb: "get"}, false)
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "pods", Subresource: "exec", Verb: "create"}, false)
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "amtd.r6security.com", Resource: "securityevents", Verb: "update"}, false)
	check(managerSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "phorvex.ai", Resource: "phorvexpolicies", Verb: "patch"}, false)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "pods", Subresource: "log", Verb: "get"}, true)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "pods", Subresource: "exec", Verb: "create"}, true)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "amtd.r6security.com", Resource: "securityevents", Verb: "update"}, true)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "phorvex.ai", Resource: "phorvexpolicies", Verb: "patch"}, true)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "persistentvolumeclaims", Verb: "get"}, false)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Resource: "configmaps", Verb: "update"}, false)
	check(consoleSA, authorizationv1.ResourceAttributes{Namespace: "default", Group: "coordination.k8s.io", Resource: "leases", Verb: "update"}, false)
}
