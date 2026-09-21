package actuator

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestNativeRBACMarkersAreLeastPrivilege keeps controller-gen's input aligned
// with the verbs the native handlers actually call. A stale marker is security
// relevant even when the separately committed runtime Role remains narrower.
func TestNativeRBACMarkersAreLeastPrivilege(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "rbac.go"))
	if err != nil {
		t.Fatalf("read rbac.go: %v", err)
	}

	const prefix = "// +kubebuilder:rbac:"
	var got []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			got = append(got, strings.TrimPrefix(line, prefix))
		}
	}
	sort.Strings(got)
	want := []string{
		`namespace=phorvex-tenant,groups="",resources=pods,verbs=get;list;delete;update;patch`,
		`namespace=phorvex-tenant,groups="",resources=pods/ephemeralcontainers,verbs=update`,
		`namespace=phorvex-tenant,groups="",resources=services,verbs=get;list;update`,
		`namespace=phorvex-tenant,groups="",resources=replicationcontrollers,verbs=get`,
		`namespace=phorvex-tenant,groups=apps,resources=replicasets;statefulsets;daemonsets;deployments,verbs=get`,
		`namespace=phorvex-tenant,groups=batch,resources=jobs,verbs=get`,
		`namespace=phorvex-tenant,groups=discovery.k8s.io,resources=endpointslices,verbs=list`,
		`namespace=phorvex-tenant,groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;delete;update`,
	}
	sort.Strings(want)

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("native RBAC marker contract drifted\n got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

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
		if len(verbs) != 1 || verbs[0] != `verbs: ["get", "list", "update"]` {
			t.Errorf("%s Service grants = %v, want exactly get/list/update", path, verbs)
		}
		if path == "../../config/rbac/phorvex-actuator-role.yaml" && strings.Contains(text, `resources: ["secrets"]`) {
			t.Errorf("%s must not gain an unconfigured standing Secret grant", path)
		}
		endpointVerbs := singleResourceVerbs(text, `resources: ["endpointslices"]`)
		wantEndpointVerbs := []string{`verbs: ["list"]`}
		if path == "../../charts/phorvex/templates/rbac.yaml" {
			// The manager's cluster Role observes exact Service membership for
			// shared capacity while the namespaced actuator Role remains list-only.
			wantEndpointVerbs = []string{`verbs: ["get", "list", "watch"]`, `verbs: ["list"]`}
		}
		if strings.Join(endpointVerbs, "\n") != strings.Join(wantEndpointVerbs, "\n") {
			t.Errorf("%s EndpointSlice grants = %v, want %v", path, endpointVerbs, wantEndpointVerbs)
		}
		for _, forbidden := range []string{"create", "update", "patch", "delete"} {
			if strings.Contains(strings.Join(endpointVerbs, " "), `"`+forbidden+`"`) {
				t.Errorf("%s grants forbidden EndpointSlice %s", path, forbidden)
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
	if !strings.Contains(chartText, `resources: ["secrets"]`) || !strings.Contains(chartText, `resourceNames: [{{ required "servingSecurity binding secretName is required" .secretName | quote }}]`) || !strings.Contains(chartText, `verbs: ["get"]`) {
		t.Error("configured serving credentials require only exact-name Secret get")
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
