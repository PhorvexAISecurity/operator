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
	add("", "services", "get", "list", "update")
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
			if err != nil || !reflect.DeepEqual(got, m007Expected(false)) {
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
