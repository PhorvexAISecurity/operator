/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * Actual Helm rendering of the chart (not string search over templates): with
 * codeExecAdmission.enabled=true the VAP + Binding + minimal resourceName-scoped read grant
 * render (Deny / failurePolicy:Fail / managed scope), the rendered VAP spec EQUALS the trusted
 * contract, and NO ephemeral-container write (execution) grant appears; with enabled=false none
 * of them render. Requires a helm binary: set HELM_BIN or have helm on PATH. If absent, the test
 * SKIPS with a precise message rather than silently downgrading the requirement (the published
 * evidence carries the executed render from a real helm binary).
 */

package codeexec

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

func helmBin(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("HELM_BIN"); b != "" {
		return b
	}
	if b, err := exec.LookPath("helm"); err == nil {
		return b
	}
	t.Skip("helm binary not found (set HELM_BIN or add helm to PATH); executed render is in evidence/l0-l2/helm-render-*.yaml")
	return ""
}

func chartDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "charts", "phorvex")
}

func render(t *testing.T, enabled string) string {
	t.Helper()
	cmd := exec.Command(helmBin(t), "template", "codeexec-test", chartDir(t),
		"--set", "phorvex.codeExecAdmission.enabled="+enabled)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template (enabled=%s): %v\n%s", enabled, err, errb.String())
	}
	return out.String()
}

// docsByKind splits a multi-doc render and returns the raw docs whose `kind:` matches.
func docsByKind(rendered, kind string) []string {
	var got []string
	for _, d := range strings.Split(rendered, "\n---") {
		if strings.Contains(d, "\nkind: "+kind+"\n") || strings.HasPrefix(strings.TrimSpace(d), "kind: "+kind) {
			got = append(got, d)
		}
	}
	return got
}

// codeexecDocsByKind is docsByKind restricted to THIS feature's objects. The chart also ships
// M-94's default-on SecurityEvent creator-identity policy + binding, which are the same kinds
// and are not what these tests are about; every code-exec object carries the policy label.
func codeexecDocsByKind(rendered, kind string) []string {
	var got []string
	for _, d := range docsByKind(rendered, kind) {
		if strings.Contains(d, "phorvex.ai/policy: codeexec-ephemeral") {
			got = append(got, d)
		}
	}
	return got
}

func TestHelmRenderEnabledProducesEnforcementAndReadGrant(t *testing.T) {
	rendered := render(t, "true")

	vaps := codeexecDocsByKind(rendered, "ValidatingAdmissionPolicy")
	if len(vaps) != 1 {
		t.Fatalf("enabled render must contain exactly one ValidatingAdmissionPolicy, got %d", len(vaps))
	}
	bindings := codeexecDocsByKind(rendered, "ValidatingAdmissionPolicyBinding")
	if len(bindings) != 1 {
		t.Fatalf("enabled render must contain exactly one Binding, got %d", len(bindings))
	}

	// The rendered VAP is a valid typed object whose spec EQUALS the trusted contract.
	var vap admissionv1.ValidatingAdmissionPolicy
	if err := yaml.Unmarshal([]byte(vaps[0]), &vap); err != nil {
		t.Fatalf("rendered VAP does not parse: %v", err)
	}
	if why := validatePolicyContent(&vap); why != "" {
		t.Fatalf("rendered VAP is not the trusted contract: %s", why)
	}
	var binding admissionv1.ValidatingAdmissionPolicyBinding
	if err := yaml.Unmarshal([]byte(bindings[0]), &binding); err != nil {
		t.Fatalf("rendered Binding does not parse: %v", err)
	}
	if why := validateBindingContent(&binding); why != "" {
		t.Fatalf("rendered Binding is not the trusted contract: %s", why)
	}

	// The minimal resourceName-scoped read grant renders; NO ephemeral-container write grant does.
	if !strings.Contains(rendered, `resourceNames: ["phorvex-codeexec-ephemeral"]`) {
		t.Fatal("enabled render must include the resourceName-scoped read grant")
	}
	// No RBAC (Cluster)Role may grant pods/ephemeralcontainers (the execution grant stays unbound).
	// Checked on RBAC docs only — the VAP legitimately NAMES pods/ephemeralcontainers as the
	// subresource it validates, which is not a grant.
	for _, kind := range []string{"ClusterRole", "Role"} {
		for _, d := range docsByKind(rendered, kind) {
			if strings.Contains(d, "ephemeralcontainers") {
				t.Fatalf("enabled render must NOT bind pods/ephemeralcontainers in a %s (execution grant)", kind)
			}
		}
	}
}

func TestHelmRenderDisabledProducesNothing(t *testing.T) {
	rendered := render(t, "false")
	if len(codeexecDocsByKind(rendered, "ValidatingAdmissionPolicy")) != 0 {
		t.Fatal("disabled render must not contain a ValidatingAdmissionPolicy")
	}
	if len(codeexecDocsByKind(rendered, "ValidatingAdmissionPolicyBinding")) != 0 {
		t.Fatal("disabled render must not contain a Binding")
	}
	if strings.Contains(rendered, "codeexec-managed") || strings.Contains(rendered, `resourceNames: ["phorvex-codeexec-ephemeral"]`) {
		t.Fatal("disabled render must not contain the code-exec scope label or read grant")
	}
}
