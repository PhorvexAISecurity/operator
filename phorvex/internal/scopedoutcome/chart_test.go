package scopedoutcome

import (
	"os/exec"
	"strings"
	"testing"
)

func renderScopedOutcomeChart(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	args := []string{"template", "m106", "../../charts/phorvex", "--namespace", "phorvex-system"}
	for _, set := range sets {
		args = append(args, "--set-string", set)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	return string(out), err
}

func TestPost25M106ChartScopedOutcomeDefaultDisabled(t *testing.T) {
	out, err := renderScopedOutcomeChart(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, forbidden := range []string{"--scoped-outcome-config=", "name: scoped-outcome-config", "name: scoped-outcome-tls", "name: scoped-outcome-evidence"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("disabled chart rendered %q", forbidden)
		}
	}
}

func TestPost25M106ChartMountsExactPrivateRuntime(t *testing.T) {
	out, err := renderScopedOutcomeChart(t,
		"phorvex.scopedOutcome.enabled=true", "phorvex.scopedOutcome.configSecretName=m106-config",
		"phorvex.scopedOutcome.tlsSecretName=m106-tls", "phorvex.scopedOutcome.existingClaim=m106-evidence")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, want := range []string{
		"type: Recreate", "fsGroup: 65532", "--scoped-outcome-config=/etc/phorvex-scoped-outcome/config/startup.json",
		"secretName: m106-config", "secretName: m106-tls", "claimName: m106-evidence",
		"mountPath: /etc/phorvex-scoped-outcome/config", "mountPath: /etc/phorvex-scoped-outcome/tls", "mountPath: /var/lib/phorvex-scoped-outcome",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("enabled chart missing %q", want)
		}
	}
	if got := strings.Count(out, "readOnly: true"); got < 2 {
		t.Errorf("TLS/config mounts were not read-only: count=%d", got)
	}
}

func TestPost25M106ChartRefusesIncompleteOrSharedRuntime(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{name: "missing identities", sets: []string{"phorvex.scopedOutcome.enabled=true"}, want: "configSecretName required"},
		{name: "overlapping mount", sets: []string{"phorvex.scopedOutcome.enabled=true", "phorvex.scopedOutcome.configSecretName=c", "phorvex.scopedOutcome.tlsSecretName=t", "phorvex.scopedOutcome.existingClaim=e", "phorvex.scopedOutcome.tlsMountPath=/etc/phorvex-scoped-outcome/config"}, want: "distinct absolute paths"},
		{name: "audit PVC", sets: []string{"phorvex.scopedOutcome.enabled=true", "phorvex.scopedOutcome.configSecretName=c", "phorvex.scopedOutcome.tlsSecretName=t", "phorvex.scopedOutcome.existingClaim=m106-phorvex-audit", "phorvex.audit.enabled=true"}, want: "dedicated from audit persistence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderScopedOutcomeChart(t, tc.sets...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("helm err=%v output=%s", err, out)
			}
		})
	}
}
