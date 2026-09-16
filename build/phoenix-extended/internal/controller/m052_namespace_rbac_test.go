package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func m052NamespaceGetRule(t *testing.T, manifests []byte, roleName string) {
	t.Helper()
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifests), 4096)
	found := false
	for {
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if raw["kind"] != "ClusterRole" {
			continue
		}
		metadata, _ := raw["metadata"].(map[string]interface{})
		if metadata["name"] != roleName {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		role := &rbacv1.ClusterRole{}
		if err := json.Unmarshal(encoded, role); err != nil {
			t.Fatal(err)
		}
		for _, rule := range role.Rules {
			mentionsNamespaces := false
			for _, resource := range rule.Resources {
				mentionsNamespaces = mentionsNamespaces || resource == "namespaces" || resource == "*"
			}
			if !mentionsNamespaces {
				continue
			}
			if len(rule.APIGroups) != 1 || rule.APIGroups[0] != "" || !reflect.DeepEqual(rule.Resources, []string{"namespaces"}) || !reflect.DeepEqual(rule.Verbs, []string{"get"}) {
				t.Fatalf("ClusterRole %q broadens namespace access: %+v", roleName, rule)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("ClusterRole %q lacks exact core/namespaces get-only rule", roleName)
	}
}

func TestM052StandalonePhoenixNamespaceReadRBAC(t *testing.T) {
	source, err := os.ReadFile("../../config/rbac/role.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m052NamespaceGetRule(t, source, "manager-role")
	helm := os.Getenv("HELM_BIN")
	if helm == "" {
		helm, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("helm binary unavailable")
		}
	}
	cmd := exec.Command(helm, "template", "m052", "../../charts/phoenix")
	var rendered, diagnostics bytes.Buffer
	cmd.Stdout = &rendered
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatalf("render Phoenix chart: %v\n%s", err, diagnostics.String())
	}
	m052NamespaceGetRule(t, rendered.Bytes(), "operator-manager-role")
}
