/*
 * Phorvex — M-21: the CHART's half of the actuator configuration, by real Helm rendering.
 *
 * The binary's omission default and a Helm value are different things, and the chart must
 * keep them distinguishable: the shipped default renders NO env var (so the binary's own
 * documented default applies), and any value an operator sets is passed through VERBATIM
 * so the binary — not the chart — is the single place that validates it. Requires a helm
 * binary: set HELM_BIN or put helm on PATH, otherwise the test SKIPS with a precise
 * message rather than silently downgrading the requirement.
 */

package actuator

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func chartHelm(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("HELM_BIN"); b != "" {
		return b
	}
	if b, err := exec.LookPath("helm"); err == nil {
		return b
	}
	t.Skip("helm binary not found (set HELM_BIN or add helm to PATH)")
	return ""
}

func renderChart(t *testing.T, sets ...string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	chart := filepath.Join(filepath.Dir(thisFile), "..", "..", "charts", "phorvex")
	args := []string{"template", "m021-test", chart}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command(chartHelm(t), args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template %v: %v\n%s", sets, err, errb.String())
	}
	return out.String()
}

// actuatorEnvValue extracts the rendered PHORVEX_ACTUATOR value; ok=false means the chart
// rendered no such env var at all, which is how the binary default is selected.
func actuatorEnvValue(rendered string) (string, bool) {
	lines := strings.Split(rendered, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "- name: "+BackendEnvVar {
			continue
		}
		if i+1 < len(lines) {
			v := strings.TrimSpace(lines[i+1])
			if rest, found := strings.CutPrefix(v, "value:"); found {
				return strings.Trim(strings.TrimSpace(rest), `"`), true
			}
		}
		return "", true
	}
	return "", false
}

// TestChartDefaultRendersNoSelector: the installed default is preserved. The chart must
// not start naming a backend of its own — that would make the binary's documented default
// unreachable and would be exactly the silent default change M-21 is not authorized to make.
func TestChartDefaultRendersNoSelector(t *testing.T) {
	if v, present := actuatorEnvValue(renderChart(t)); present {
		t.Fatalf("the shipped default must render NO %s (so the binary default applies), got %q",
			BackendEnvVar, v)
	}
	// And the binary default that then applies is still phoenix.
	res, err := ResolveBackend("", false)
	if err != nil || res.Backend != BackendPhoenix || res.Source != SourceDefault {
		t.Fatalf("the unconfigured resolution must be the phoenix default, got %+v (%v)", res, err)
	}
}

// TestChartPassesEveryAcceptedValueVerbatim: each accepted value reaches the pod exactly as
// written and resolves to the matching backend.
func TestChartPassesEveryAcceptedValueVerbatim(t *testing.T) {
	for _, b := range Backends() {
		v, present := actuatorEnvValue(renderChart(t, "phorvex.actuator="+string(b)))
		if !present {
			t.Fatalf("phorvex.actuator=%s rendered no %s", b, BackendEnvVar)
		}
		if v != string(b) {
			t.Fatalf("phorvex.actuator=%s rendered %q", b, v)
		}
		res, err := ResolveBackend(v, true)
		if err != nil || res.Backend != b || res.Source != SourceExplicit {
			t.Fatalf("the rendered value %q must resolve to explicit %s, got %+v (%v)", v, b, res, err)
		}
	}
}

// TestChartDoesNotSanitiseAnInvalidValue: the chart passes a bad value through unchanged so
// the BINARY rejects it at startup. If the chart trimmed or case-folded it, an operator's
// typo would once again become a silent, working configuration — and the pod would come up
// green on a backend nobody chose.
func TestChartDoesNotSanitiseAnInvalidValue(t *testing.T) {
	for _, bad := range []string{"NATIVE", "phoenixx"} {
		v, present := actuatorEnvValue(renderChart(t, "phorvex.actuator="+bad))
		if !present {
			t.Fatalf("phorvex.actuator=%q rendered no %s", bad, BackendEnvVar)
		}
		if v != bad {
			t.Fatalf("the chart must not rewrite %q, it rendered %q", bad, v)
		}
		if _, err := ResolveBackend(v, true); err == nil {
			t.Fatalf("the rendered %q must be rejected by the binary", v)
		}
	}
}
