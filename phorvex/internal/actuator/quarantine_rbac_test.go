package actuator

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM048NativeMutationInventory(t *testing.T) {
	want := []authz.Verb{{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "create"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "update"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "delete"}, {Resource: "pods", Verb: "update"}}
	if !reflect.DeepEqual(actionVerbs[model.ActionQuarantine], want) {
		t.Fatalf("native quarantine mutation inventory: %+v", actionVerbs[model.ActionQuarantine])
	}
	// The known pure-native capability-routing gap is M160, not this permission fix.
	if !reflect.DeepEqual(RequiredVerbs(model.ActionQuarantine), phoenixRuleVerbs) {
		t.Fatal("RequiredVerbs routing changed")
	}
}

func m048RoutineRole(t *testing.T, path string) rbacv1.Role {
	t.Helper()
	for _, r := range m007ReadRoles(t, path) {
		if strings.HasSuffix(r.Name, "-actuator-routine") {
			return r
		}
	}
	t.Fatalf("missing routine Role in %s", path)
	return rbacv1.Role{}
}
func TestM048QuarantineRoleContract(t *testing.T) {
	template, err := os.ReadFile("../../charts/phorvex/templates/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wantPolicyGrants := []string{`verbs: ["get", "list", "watch"]`, `verbs: ["create", "get", "list", "delete", "update"]`}
	if !reflect.DeepEqual(singleResourceVerbs(string(template), `resources: ["networkpolicies"]`), wantPolicyGrants) {
		t.Fatal("scanner/native policy grants differ from exact contract")
	}
	source := m048RoutineRole(t, "../../config/rbac/phorvex-actuator-role.yaml")
	got, err := m007Grants(source)
	if err != nil || !reflect.DeepEqual(got, m007Expected(false)) {
		t.Fatal("unexpected role expansion or omission", got, err)
	}
	// Independently enumerate the only policy permissions, including the forbidden patch.
	var policyVerbs []string
	for _, r := range source.Rules {
		if reflect.DeepEqual(r.APIGroups, []string{"networking.k8s.io"}) && reflect.DeepEqual(r.Resources, []string{"networkpolicies"}) {
			policyVerbs = append(policyVerbs, r.Verbs...)
		}
	}
	if !reflect.DeepEqual(policyVerbs, []string{"create", "get", "list", "delete", "update"}) {
		t.Fatal("policy contract", policyVerbs)
	}
	if path := os.Getenv("M048_RENDERED_RBAC"); path != "" {
		rendered := m048RoutineRole(t, path)
		if rendered.Namespace != "phorvex-tenant" || !reflect.DeepEqual(source.Rules, rendered.Rules) {
			t.Fatal("rendered/source Role rules or opted-in namespace differ")
		}
	}
}

// Real authorizer + actual dispatch/handler: admin seeds fixtures and drift, but
// every handler read/write uses an impersonated identity with only the exact Role.
func TestM048APIServerRestrictedRole(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated API server")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
	e.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := qtnScheme()
	_ = rbacv1.AddToScheme(scheme)
	_ = authorizationv1.AddToScheme(scheme)
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	create := func(o client.Object) {
		t.Helper()
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	const ns = "m048-rbac"
	for _, name := range []string{ns, "m048-unbound", "operator"} {
		create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	}
	create(&v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: ns}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionQuarantine)}}}})
	create(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "m048-authority-namespace-read"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}}}})
	source := m048RoutineRole(t, "../../config/rbac/phorvex-actuator-role.yaml")
	clients := map[string]client.Client{}
	for _, identity := range []string{"old", "updated"} {
		role := source.DeepCopy()
		role.Namespace = ns
		role.Name = identity
		if identity == "old" {
			for i := range role.Rules {
				r := &role.Rules[i]
				if reflect.DeepEqual(r.Resources, []string{"networkpolicies"}) {
					var verbs []string
					for _, v := range r.Verbs {
						if v != "update" {
							verbs = append(verbs, v)
						}
					}
					r.Verbs = verbs
				}
			}
		}
		create(role)
		create(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: identity, Namespace: ns}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: identity}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: identity, Namespace: ns}}})
		create(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: identity + "-policy-read", Namespace: ns}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"phorvex.ai"}, Resources: []string{"phorvexpolicies"}, Verbs: []string{"get"}}}})
		create(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: identity + "-policy-read", Namespace: ns}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: identity + "-policy-read"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: identity, Namespace: ns}}})
		create(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: identity + "-operation-journal", Namespace: "operator"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "create", "update", "delete"}}}})
		create(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: identity + "-operation-journal", Namespace: "operator"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: identity + "-operation-journal"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: identity, Namespace: ns}}})
		create(&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: identity + "-authority-namespace-read"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "m048-authority-namespace-read"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: identity, Namespace: ns}}})
		username := "system:serviceaccount:" + ns + ":" + identity
		groups := []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + ns}
		// Wait only for observed authorizer readiness; no handler mutation is retried
		// on an arbitrary timer and a denial remains a real test assertion below.
		err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			for _, a := range []authorizationv1.ResourceAttributes{{Namespace: ns, Resource: "pods", Verb: "update"}, {Namespace: ns, Resource: "pods", Verb: "list"}, {Namespace: ns, Resource: "services", Verb: "list"}, {Namespace: ns, Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "create"}, {Namespace: ns, Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "update"}, {Namespace: ns, Group: "phorvex.ai", Resource: "phorvexpolicies", Verb: "get"}, {Resource: "namespaces", Verb: "get"}, {Namespace: "operator", Resource: "configmaps", Verb: "create"}, {Namespace: "operator", Resource: "configmaps", Verb: "update"}} {
				review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: username, Groups: groups, ResourceAttributes: &a}}
				if err := admin.Create(ctx, review); err != nil {
					return false, err
				}
				want := !(identity == "old" && a.Resource == "networkpolicies" && a.Verb == "update")
				if review.Status.Allowed != want {
					return false, nil
				}
			}
			return true, nil
		})
		if err != nil {
			t.Fatalf("authorizer readiness %s: %v", identity, err)
		}
		restrictedConfig := rest.CopyConfig(cfg)
		restrictedConfig.Impersonate = rest.ImpersonationConfig{UserName: username, Groups: groups}
		restricted, err := client.New(restrictedConfig, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		clients[identity] = restricted
	}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: ns, Labels: map[string]string{"app": "x"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "unused:test"}}}}
	create(p)
	old := clients["old"]
	updated := clients["updated"]
	result, err := m048Dispatch(old, p)
	if err != nil || !result.Emitted {
		t.Fatalf("old Role initial create positive control: %+v %v", result, err)
	}
	policy := m048GetPolicy(t, admin, p)
	t.Logf("old Role create succeeded: PodUID=%s policyUID=%s", p.UID, policy.UID)
	policy.Spec.PodSelector = metav1.LabelSelector{}
	policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
	m048Update(t, admin, policy)
	before := policy.DeepCopy()
	result, err = m048Dispatch(old, p)
	if !apierrors.IsForbidden(err) || result.Emitted {
		t.Fatalf("old Role must deny repair: %+v %v", result, err)
	}
	if !reflect.DeepEqual(before, m048GetPolicy(t, admin, p)) {
		t.Fatal("denied repair changed policy")
	}
	t.Logf("old Role repair denial: %v", err)
	result, err = m048Dispatch(updated, p)
	if err != nil || !result.Emitted {
		t.Fatalf("updated exact Role repair: %+v %v", result, err)
	}
	policy = m048GetPolicy(t, admin, p)
	if err = verifyQuarantineTarget(ctx, EnactCtx{Client: updated, Reader: updated}, m048GetPod(t, admin, p), policy); err != nil {
		t.Fatal(err)
	}
	if policy.UID != before.UID {
		t.Fatal("repair replaced policy")
	}
	t.Logf("updated Role repair/readback succeeded: policyUID=%s RV=%s", policy.UID, policy.ResourceVersion)
	result, err = m048Dispatch(updated, p)
	if err != nil || result.Emitted {
		t.Fatal("restricted retry not idempotent", result, err)
	}

	// Seed denied fixtures as admin, so NotFound cannot masquerade as denial.
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: ns}}
	create(secret)
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: ns}}
	create(configMap)
	otherConfigMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "m048-unbound"}}
	create(otherConfigMap)
	otherPod := p.DeepCopy()
	otherPod.Namespace = "m048-unbound"
	otherPod.ResourceVersion = ""
	otherPod.UID = ""
	create(otherPod)
	otherPolicy := quarantinePolicy(otherPod)
	create(otherPolicy)
	if err := updated.Patch(ctx, p, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"annotations":{"phorvex.ai/recovery-patch":"allowed"}}}`))); err != nil {
		t.Fatalf("configured namespace Pod patch denied: %v", err)
	}
	patched := m048GetPod(t, admin, p)
	if patched.Annotations["phorvex.ai/recovery-patch"] != "allowed" {
		t.Fatalf("configured namespace Pod patch not persisted: %+v", patched.Annotations)
	}
	denied := map[string]func() error{
		"policy-patch": func() error {
			return updated.Patch(ctx, policy, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"annotations":{"unauthorized":"yes"}}}`)))
		},
		"other-namespace-policy-update": func() error {
			otherPolicy.Spec.PodSelector = metav1.LabelSelector{}
			return updated.Update(ctx, otherPolicy)
		},
		"other-namespace-pod-patch": func() error {
			return updated.Patch(ctx, otherPod, client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"annotations":{"unauthorized":"yes"}}}`)))
		},
		"other-namespace-pod-read": func() error { return updated.Get(ctx, client.ObjectKeyFromObject(otherPod), &corev1.Pod{}) },
		"secret-read":              func() error { return updated.Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{}) },
		// The routine Role deliberately grants get/update on ConfigMaps in its own
		// namespace for the sensitive-output-policy-activate CAS (4fc5fec4; pinned by
		// TestM048QuarantineRoleContract). Every other ConfigMap write stays denied.
		"configmap-create": func() error {
			return updated.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unauthorized", Namespace: ns}})
		},
		"configmap-delete": func() error { return updated.Delete(ctx, configMap) },
		"other-namespace-configmap-update": func() error {
			otherConfigMap.Data = map[string]string{"unauthorized": "yes"}
			return updated.Update(ctx, otherConfigMap)
		},
	}
	for name, operation := range denied {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !apierrors.IsForbidden(err) {
				t.Fatalf("expected Forbidden, got %v", err)
			}
		})
	}
	if !reflect.DeepEqual(policy, m048GetPolicy(t, admin, p)) {
		t.Fatal("denied patch altered canonical policy")
	}
}
