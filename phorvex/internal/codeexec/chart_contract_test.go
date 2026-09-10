/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * Static chart/manifest contract for the code-exec admission package (an L0-L2 "chart render"
 * check without a helm binary, matching internal/actuator/rbac_contract_test.go's style):
 *   - the VAP is Deny + failurePolicy:Fail, version-pinned, scoped to the managed label, and
 *     targets pods/ephemeralcontainers UPDATE;
 *   - the emitted profile the VAP allows (digest / securityContext / Option A / custom-inject)
 *     is present verbatim;
 *   - the runtime read grant is resourceName-scoped GET only (no list/watch/write), gated by
 *     the off-by-default flag, and no ephemeral-container WRITE grant is bound by the chart;
 *   - the standalone config manifest and the chart template agree on the load-bearing fields.
 */

package codeexec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	// internal/codeexec -> repo root (phorvex/)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

func mustContain(t *testing.T, name, hay string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(hay, n) {
			t.Errorf("%s: missing required content %q", name, n)
		}
	}
}

// vapContent asserts the load-bearing VAP fields the verifier and the enforcement both rely on.
func vapContent(t *testing.T, name, text string) {
	t.Helper()
	mustContain(t, name, text,
		"failurePolicy: Fail",
		`validationActions: ["Deny"]`,
		`phorvex.ai/policy-version: "m6-1"`,
		`phorvex.ai/codeexec-managed: "true"`,
		"pods/ephemeralcontainers",
		`operations: ["UPDATE"]`,
		"policyName: phorvex-codeexec-ephemeral",
		// the paired profile the VAP allows:
		"busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f",
		"ec.securityContext.runAsUser == 65534",
		"ec.securityContext.capabilities.drop == ['ALL']",
		"'RuntimeDefault'",
		"['sh', '-c']",
		"['echo phorvex-custom-action; sleep 1']",
		// Option A: debugger command AND args required empty.
		"ec.name == 'phorvex-debugger'",
	)
}

func TestVAPConfigManifestContract(t *testing.T) {
	vapContent(t, "config/admission", repoFile(t, "config/admission/codeexec-ephemeral-vap.yaml"))
}

// TestConfigManifestEqualsTrustedContract proves the deployed config/admission manifest's
// enforcement spec is byte-identical (normalized) to the embedded trusted contract the verifier
// checks against — so the policy the installer applies and the policy the runtime demands cannot
// drift. (The rendered Helm chart's agreement is proven in chart_render_test.go.)
func TestConfigManifestEqualsTrustedContract(t *testing.T) {
	p, b, err := ParseContract([]byte(repoFile(t, "config/admission/codeexec-ephemeral-vap.yaml")))
	if err != nil {
		t.Fatalf("parse config manifest: %v", err)
	}
	if why := validatePolicyContent(p); why != "" {
		t.Fatalf("config VAP spec != trusted contract: %s", why)
	}
	if why := validateBindingContent(b); why != "" {
		t.Fatalf("config Binding spec != trusted contract: %s", why)
	}
}

func TestVAPChartTemplateContract(t *testing.T) {
	text := repoFile(t, "charts/phorvex/templates/codeexec-admission.yaml")
	vapContent(t, "chart", text)
	// Gated off by default: the whole template is wrapped in the enable flag.
	mustContain(t, "chart", text, "{{- if .Values.phorvex.codeExecAdmission.enabled }}")
}

func TestCodeExecAdmissionDefaultsOff(t *testing.T) {
	values := repoFile(t, "charts/phorvex/values.yaml")
	// The block must exist and default to disabled.
	if !strings.Contains(values, "codeExecAdmission:") {
		t.Fatal("values.yaml: missing codeExecAdmission block")
	}
	idx := strings.Index(values, "codeExecAdmission:")
	after := values[idx:]
	nextEnabled := strings.Index(after, "enabled:")
	if nextEnabled < 0 || !strings.Contains(after[nextEnabled:nextEnabled+20], "false") {
		t.Fatal("values.yaml: codeExecAdmission.enabled must default to false")
	}
}

func TestRuntimeReadGrantIsResourceNameScopedGetOnly(t *testing.T) {
	rbac := repoFile(t, "charts/phorvex/templates/rbac.yaml")
	mustContain(t, "rbac", rbac,
		"{{- if .Values.phorvex.codeExecAdmission.enabled }}",
		`resources: ["validatingadmissionpolicies", "validatingadmissionpolicybindings"]`,
		`resourceNames: ["phorvex-codeexec-ephemeral"]`,
		`verbs: ["get"]`,
	)
	// The read grant must NOT smuggle list/watch or any write on those objects. Inspect just
	// the read-grant stanza (from its resourceNames line to the end of that rule's verbs).
	i := strings.Index(rbac, `resourceNames: ["phorvex-codeexec-ephemeral"]`)
	if i < 0 {
		t.Fatal("read-grant stanza not found")
	}
	stanza := rbac[i : i+120]
	for _, forbidden := range []string{"list", "watch", "create", "update", "patch", "delete"} {
		if strings.Contains(stanza, forbidden) {
			t.Errorf("read grant must be get-only; found %q in %q", forbidden, stanza)
		}
	}
}

// The chart must NOT bind any pods/ephemeralcontainers WRITE (the execution grant) — that is a
// separate, human-gated step. The manager ClusterRole and the routine actuator Role both omit it.
func TestChartBindsNoEphemeralContainersWrite(t *testing.T) {
	rbac := repoFile(t, "charts/phorvex/templates/rbac.yaml")
	if strings.Contains(rbac, "ephemeralcontainers") {
		t.Fatal("chart rbac.yaml must not grant pods/ephemeralcontainers (execution grant stays unbound)")
	}
}
