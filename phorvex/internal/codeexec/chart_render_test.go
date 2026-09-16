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

func renderWithIdentity(t *testing.T, release, namespace, enabled, managerSA string) (string, string, error) {
	t.Helper()
	args := []string{"template", release, chartDir(t), "--namespace", namespace,
		"--set", "phorvex.codeExecAdmission.enabled=" + enabled}
	if managerSA != "" {
		args = append(args, "--set-string", "phorvex.serviceAccountName="+managerSA)
	}
	cmd := exec.Command(helmBin(t), args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func render(t *testing.T, enabled string) string {
	t.Helper()
	out, errb, err := renderWithIdentity(t, "phorvex", "phorvex-system", enabled, "")
	if err != nil {
		t.Fatalf("helm template (enabled=%s): %v\n%s", enabled, err, errb)
	}
	return out
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

func TestHelmRenderCodeExecRejectsNonCanonicalManagerIdentity(t *testing.T) {
	const want = "requires the canonical singleton manager identity system:serviceaccount:phorvex-system:phorvex-phorvex-manager"
	tests := []struct {
		name, release, namespace, managerSA string
	}{
		{name: "custom-service-account", release: "phorvex", namespace: "phorvex-system", managerSA: "custom-manager"},
		{name: "alternate-namespace", release: "phorvex", namespace: "control-plane"},
		{name: "alternate-release-name", release: "other", namespace: "phorvex-system"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, errb, err := renderWithIdentity(t, tc.release, tc.namespace, "true", tc.managerSA)
			if err == nil {
				t.Fatal("enabled code-exec admission unexpectedly rendered with a noncanonical manager identity")
			}
			if !strings.Contains(errb, want) {
				t.Fatalf("render failed without the compatibility explanation %q:\n%s", want, errb)
			}
		})
	}
}

func TestHelmRenderCodeExecAcceptsCanonicalIdentityFromExplicitServiceAccount(t *testing.T) {
	rendered, errb, err := renderWithIdentity(t, "other-release", "phorvex-system", "true", "phorvex-phorvex-manager")
	if err != nil {
		t.Fatalf("explicit canonical manager identity: %v\n%s", err, errb)
	}
	if !strings.Contains(rendered, "serviceAccountName: phorvex-phorvex-manager") {
		t.Fatal("enabled render did not preserve the explicit canonical manager ServiceAccount")
	}
	vaps := codeexecDocsByKind(rendered, "ValidatingAdmissionPolicy")
	if len(vaps) != 1 {
		t.Fatalf("enabled canonical identity render must contain exactly one ValidatingAdmissionPolicy, got %d", len(vaps))
	}
	var vap admissionv1.ValidatingAdmissionPolicy
	if err := yaml.Unmarshal([]byte(vaps[0]), &vap); err != nil {
		t.Fatalf("rendered VAP does not parse: %v", err)
	}
	if why := validatePolicyContent(&vap); why != "" {
		t.Fatalf("rendered VAP is not the trusted contract: %s", why)
	}
}

func TestHelmRenderCustomManagerAllowedWhenCodeExecAdmissionDisabled(t *testing.T) {
	rendered, errb, err := renderWithIdentity(t, "custom-release", "custom-control", "false", "custom-manager")
	if err != nil {
		t.Fatalf("custom manager with code-exec admission disabled: %v\n%s", err, errb)
	}
	if !strings.Contains(rendered, "serviceAccountName: custom-manager") {
		t.Fatal("disabled render did not preserve the configured custom manager ServiceAccount")
	}
	if len(codeexecDocsByKind(rendered, "ValidatingAdmissionPolicy")) != 0 ||
		len(codeexecDocsByKind(rendered, "ValidatingAdmissionPolicyBinding")) != 0 {
		t.Fatal("disabled custom-manager render must not contain code-exec admission objects")
	}
}
