package actuator

import (
	"os"
	"strings"
	"testing"
)

func TestServiceRestitchRBACIsNamespacedAndExact(t *testing.T) {
	paths := []string{
		"../../config/rbac/phorvex-actuator-role.yaml",
		"../../charts/phorvex/templates/rbac.yaml",
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(raw)
		verbs := singleResourceVerbs(text, `resources: ["services"]`)
		if len(verbs) != 1 || verbs[0] != `verbs: ["get", "update"]` {
			t.Errorf("%s Service grants = %v, want exactly get/update", path, verbs)
		}
		for _, denied := range []string{`resources: ["secrets"]`, `resources: ["endpointslices"]`} {
			if strings.Contains(text, denied) {
				t.Errorf("%s grants forbidden resource via %s", path, denied)
			}
		}
	}

	chart, err := os.ReadFile("../../charts/phorvex/templates/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	chartText := string(chart)
	if !strings.Contains(chartText, "kind: Role\n") || !strings.Contains(chartText, ".Values.phorvex.actuatorNamespaces") {
		t.Error("Helm restitch permission must be an opt-in namespaced Role")
	}
}

func singleResourceVerbs(text, resourceLine string) []string {
	lines := strings.Split(text, "\n")
	var out []string
	for i, line := range lines {
		if strings.TrimSpace(line) != resourceLine {
			continue
		}
		for j := i + 1; j < len(lines) && j <= i+3; j++ {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "verbs:") {
				out = append(out, trimmed)
				break
			}
		}
	}
	return out
}
