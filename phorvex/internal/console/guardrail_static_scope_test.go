package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pinnedStaticProfile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../build/test-harness/config.guardrail-confidentiality-static.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	for placeholder, value := range map[string]string{
		"__SET_LOGICAL_CLUSTER_TARGET__":           "reviewed-cluster",
		"__SET_REVIEWED_KUBE_SYSTEM_UID__":         uid,
		"__SET_REVIEWED_VLLM_POD_NAME__":           "reviewed-vllm-pod",
		"__SET_REVIEWED_VLLM_POD_UID__":            uid,
		"__SET_REVIEWED_VLLM_SERVICE_UID__":        uid,
		"__SET_REVIEWED_GUARDRAIL_SOURCE_SHA256__": strings.Repeat("a", 64),
		"__SET_REVIEWED_GUARDRAIL_JOURNAL_NAME__":  "reviewed-gj",
		"__SET_REVIEWED_GUARDRAIL_JOURNAL_UID__":   uid,
		"__SET_REVIEWED_KV_JOURNAL_NAME__":         "reviewed-kj",
		"__SET_REVIEWED_KV_JOURNAL_UID__":          uid,
	} {
		s = strings.ReplaceAll(s, placeholder, value)
	}
	return []byte(s)
}

func TestGuardrailStaticSuiteDestinationRejectsIncompleteProfile(t *testing.T) {
	dir := t.TempDir()
	rm := NewRunManager(Config{Root: dir, HarnessDir: dir})
	path := filepath.Join(dir, allowedConfigs[guardrailStaticConfig].File)
	raw := pinnedStaticProfile(t)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dest, err := rm.SuiteDestination(guardrailStaticConfig)
	if err != nil || dest.ScopeTarget != "reviewed-cluster" || len(dest.Tenants) != 2 {
		t.Fatalf("valid reviewed profile refused: %+v %v", dest, err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"missing pod", "  podName: \"reviewed-vllm-pod\"\n", ""},
		{"wrong variant", "  variant: pgv1", "  variant: pgv2"},
		{"wrong run bound", "  maxRunSeconds: 600", "  maxRunSeconds: 601"},
		{"wrong source shape", strings.Repeat("a", 64), "bad-source"},
		{"invalid UID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "not-a-uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := []byte(strings.Replace(string(raw), tc.old, tc.new, 1))
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := rm.SuiteDestination(guardrailStaticConfig); err == nil {
				t.Fatal("incomplete profile advertised available")
			}
		})
	}
}

func TestGuardrailStaticRunScopeRequiresHostClusterAndBothTenants(t *testing.T) {
	own := runOwnership{Target: "reviewed-cluster", Tenant: "vllm", FixtureTenant: "phorvex-system", Config: guardrailStaticConfig}
	p := &Principal{Targets: []string{hostTargetID, "reviewed-cluster"}, Tenants: []string{"vllm", "phorvex-system"}}
	if !runVisibleTo(p, own) {
		t.Fatal("fully granted run hidden")
	}
	for _, tc := range []struct {
		name             string
		targets, tenants []string
	}{
		{"host revoked", []string{"reviewed-cluster"}, []string{"vllm", "phorvex-system"}},
		{"cluster revoked", []string{hostTargetID}, []string{"vllm", "phorvex-system"}},
		{"vllm revoked", []string{hostTargetID, "reviewed-cluster"}, []string{"phorvex-system"}},
		{"journal tenant revoked", []string{hostTargetID, "reviewed-cluster"}, []string{"vllm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runVisibleTo(&Principal{Targets: tc.targets, Tenants: tc.tenants}, own) {
				t.Fatal("revoked grant retained run visibility")
			}
		})
	}
}

func TestGuardrailStaticNamedItemCannotEnterGenericScenario(t *testing.T) {
	dir := t.TempDir()
	rm := NewRunManager(Config{Root: dir, HarnessDir: dir})
	for _, name := range []string{"ai-vllm-guardrail-confidentiality-static", guardrailStaticConfig} {
		if _, err := rm.StartScenario([]string{name}, false, false, "reviewed-cluster", "vllm", "", ""); err == nil {
			t.Fatal("named static item entered generic scenario")
		}
	}
	if _, err := (&Server{cfg: Config{Root: dir, HarnessDir: dir}}).catalogueSignalDefinition("ai-vllm-guardrail-confidentiality-static"); err == nil {
		t.Fatal("named static item became SecurityEvent stimulus")
	}
	if _, err := os.Stat(filepath.Join(dir, ".phorvex-console", "runs")); err == nil {
		t.Fatal("generic scenario refusal wrote run state")
	}
}
