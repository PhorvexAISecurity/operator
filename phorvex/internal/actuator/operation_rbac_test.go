package actuator

import (
	"os"
	"strings"
	"testing"
)

func TestOperationJournalChartRoleIsNamespaced(t *testing.T) {
	raw, err := os.ReadFile("../../charts/phorvex/templates/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "-operation-journal\n")
	if start < 0 {
		t.Fatal("missing journal Role")
	}
	role := text[start:]
	if !strings.Contains(role, "namespace: {{ default .Release.Namespace .Values.phorvex.operatorNamespace }}") || !strings.Contains(role, `resources: ["configmaps"]`) || !strings.Contains(role, `verbs: ["get", "list", "create", "update", "delete"]`) || !strings.Contains(role, "kind: RoleBinding") {
		t.Fatal("journal grant is not an operator-namespace Role/Binding")
	}
}
