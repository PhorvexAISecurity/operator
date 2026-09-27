package actuator

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// An independently enumerated contract, not a copy of controller-gen's output.
// It covers native handlers + orphan NetworkPolicy GC, not the whole manager SA.
func m007Expected(codeexec bool) map[string]bool {
	out := map[string]bool{}
	add := func(g, r string, vs ...string) {
		for _, v := range vs {
			out[g+"/"+r+"/"+v] = true
		}
	}
	add("", "pods", "get", "list", "delete", "update", "patch")
	add("", "configmaps", "get", "update")
	add("", "pods/eviction", "create")
	add("", "services", "get", "list", "update")
	add("discovery.k8s.io", "endpointslices", "list")
	add("", "replicationcontrollers", "get")
	for _, r := range []string{"replicasets", "deployments", "statefulsets", "daemonsets"} {
		add("apps", r, "get")
	}
	add("batch", "jobs", "get")
	add("networking.k8s.io", "networkpolicies", "get", "list", "create", "delete", "update")
	if codeexec {
		add("", "pods/ephemeralcontainers", "update")
	}
	return out
}

// The installed Helm routine Role deliberately omits blanket tenant ConfigMap
// writes. Feature-specific policy activation uses an exact resourceNames Role;
// the generated marker and standalone reference manifest remain broader review
// artifacts and retain their own contract above.
func m007RenderedRoutineExpected() map[string]bool {
	out := m007Expected(false)
	delete(out, "/configmaps/get")
	delete(out, "/configmaps/update")
	return out
}
func m007Grants(role rbacv1.Role) (map[string]bool, error) {
	if role.Kind != "Role" || role.Namespace == "" {
		return nil, fmt.Errorf("expected namespaced Role")
	}
	grants := map[string]bool{}
	for _, r := range role.Rules {
		if len(r.ResourceNames) > 0 || len(r.NonResourceURLs) > 0 {
			return nil, fmt.Errorf("unexpected restrictions/nonresource grant")
		}
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					grants[g+"/"+res+"/"+v] = true
				}
			}
		}
	}
	return grants, nil
}
func m007ReadRoles(t *testing.T, path string) []rbacv1.Role {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := kyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var roles []rbacv1.Role
	for {
		var r rbacv1.Role
		err := dec.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if r.Kind == "Role" {
			roles = append(roles, r)
		}
	}
	return roles
}
func m007ReadBindings(t *testing.T, path string) []rbacv1.RoleBinding {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := kyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var bindings []rbacv1.RoleBinding
	for {
		var b rbacv1.RoleBinding
		err := dec.Decode(&b)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if b.Kind == "RoleBinding" {
			bindings = append(bindings, b)
		}
	}
	return bindings
}

func m007RoleAllows(role rbacv1.Role, resource, name, verb string) bool {
	for _, rule := range role.Rules {
		if !containsM007(rule.APIGroups, "") || !containsM007(rule.Resources, resource) || !containsM007(rule.Verbs, verb) {
			continue
		}
		if len(rule.ResourceNames) == 0 || containsM007(rule.ResourceNames, name) {
			return true
		}
	}
	return false
}

func containsM007(values []string, want string) bool {
	for _, value := range values {
		if value == want || value == "*" {
			return true
		}
	}
	return false
}

func TestM007LiteLLMExactOptInGrant(t *testing.T) {
	disabled, enabled := os.Getenv("M007_RENDERED_RBAC"), os.Getenv("M007_LITELLM_RENDERED_RBAC")
	if disabled == "" || enabled == "" {
		t.Skip("requires the disabled and LiteLLM-enabled Helm renders")
	}
	const name = "m007-phorvex-litellm-client-revoke"
	for _, role := range m007ReadRoles(t, disabled) {
		if role.Name == name {
			t.Fatal("disabled profile granted LiteLLM policy mutation")
		}
	}
	for _, binding := range m007ReadBindings(t, disabled) {
		if binding.Name == name {
			t.Fatal("disabled profile bound LiteLLM policy mutation")
		}
	}
	var matches int
	for _, role := range m007ReadRoles(t, enabled) {
		if role.Name != name {
			continue
		}
		matches++
		want := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"},
			ResourceNames: []string{"phorvex-litellm-client-policy"}, Verbs: []string{"get", "update"}}}
		if role.Namespace != "litellm" || !reflect.DeepEqual(role.Rules, want) {
			t.Fatalf("exact owned policy grant differs or authorizes wrong ConfigMap/Secret: %+v", role)
		}
		if !m007RoleAllows(role, "configmaps", "phorvex-litellm-client-policy", "get") ||
			!m007RoleAllows(role, "configmaps", "phorvex-litellm-client-policy", "update") ||
			m007RoleAllows(role, "configmaps", "other-policy", "update") ||
			m007RoleAllows(role, "secrets", "exact-status-token", "update") {
			t.Fatal("LiteLLM policy role allowed wrong ConfigMap/Secret or denied exact policy")
		}
	}
	if matches != 1 {
		t.Fatalf("expected one exact LiteLLM policy Role, got %d", matches)
	}
	matches = 0
	for _, binding := range m007ReadBindings(t, enabled) {
		if binding.Name != name {
			continue
		}
		matches++
		wantSubject := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "m007-phorvex-manager", Namespace: "phorvex-system"}}
		if binding.Namespace != "litellm" || binding.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name}) ||
			!reflect.DeepEqual(binding.Subjects, wantSubject) {
			t.Fatalf("exact owned policy binding differs: %+v", binding)
		}
	}
	if matches != 1 {
		t.Fatalf("expected one exact LiteLLM policy binding, got %d", matches)
	}
}
func TestM007GeneratedAndRoutineContracts(t *testing.T) {
	roles := m007ReadRoles(t, "../../config/rbac/generated-native/role.yaml")
	if len(roles) != 1 {
		t.Fatal("expected one unbound marker-union Role")
	}
	generated := roles[0]
	if generated.Namespace != "phorvex-tenant" || generated.Name != "phorvex-native-marker-contract" {
		t.Fatal("generated scope changed")
	}
	got, err := m007Grants(generated)
	if err != nil || !reflect.DeepEqual(got, m007Expected(true)) {
		t.Fatalf("generated contract: %v %v", got, err)
	}
	for _, path := range []string{"../../config/rbac/phorvex-actuator-role.yaml", os.Getenv("M007_RENDERED_RBAC")} {
		if path == "" {
			continue
		}
		found := false
		for _, r := range m007ReadRoles(t, path) {
			if r.Name != "phorvex-actuator-routine" && r.Name != "m007-phorvex-actuator-routine" {
				continue
			}
			found = true
			got, err := m007Grants(r)
			want := m007Expected(false)
			if path == os.Getenv("M007_RENDERED_RBAC") {
				want = m007RenderedRoutineExpected()
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s routine contract: %v %v", path, got, err)
			}
		}
		if !found {
			t.Fatalf("%s missing routine Role", path)
		}
	}
	// Negative controls exercise the semantic check in both directions, including
	// grouped resource/verb Cartesian expansion and scope expansion.
	for _, kind := range []string{"pod-create", "remove-update", "cluster-scope", "wildcard"} {
		t.Run(kind, func(t *testing.T) {
			r := generated.DeepCopy()
			switch kind {
			case "pod-create":
				r.Rules = append(r.Rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}})
			case "remove-update":
				for i := range r.Rules {
					var vs []string
					for _, v := range r.Rules[i].Verbs {
						if v != "update" {
							vs = append(vs, v)
						}
					}
					r.Rules[i].Verbs = vs
				}
			case "cluster-scope":
				r.Kind = "ClusterRole"
				r.Namespace = ""
			case "wildcard":
				r.Rules[0].Verbs = append(r.Rules[0].Verbs, "*")
			}
			got, err := m007Grants(*r)
			if err == nil && reflect.DeepEqual(got, m007Expected(true)) {
				t.Fatal("bad mutation accepted")
			}
		})
	}
}
