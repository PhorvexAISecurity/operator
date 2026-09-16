package actuator

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func renderM052Chart(t *testing.T, flag, value string) (string, error) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	chart := filepath.Join(filepath.Dir(thisFile), "..", "..", "charts", "phorvex")
	args := []string{"template", "m052-test", chart}
	if value != "" {
		args = append(args, flag, "phorvex.maxRetainedQuarantinesPerNamespace="+value)
	}
	out, err := exec.Command(chartHelm(t), args...).CombinedOutput()
	return string(out), err
}

func TestM052ChartQuarantineCapacityDefaultAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flag  string
		value string
		want  string
	}{
		{name: "default", want: "--max-retained-quarantines-per-namespace=1"},
		{name: "disabled", flag: "--set", value: "0", want: "--max-retained-quarantines-per-namespace=0"},
		{name: "upper-bound", flag: "--set", value: "128", want: "--max-retained-quarantines-per-namespace=128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderM052Chart(t, tc.flag, tc.value)
			if err != nil || !strings.Contains(out, tc.want) {
				t.Fatalf("helm render err=%v want=%q\n%s", err, tc.want, out)
			}
		})
	}
}

func TestM052ChartRejectsInvalidQuarantineCapacity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flag  string
		value string
		want  string
	}{
		{name: "negative", flag: "--set", value: "-1", want: "non-negative whole number"},
		{name: "fractional", flag: "--set", value: "1.5", want: "non-negative whole number"},
		{name: "above-bound", flag: "--set", value: "129", want: "must not exceed 128"},
		{name: "leading-zero", flag: "--set-string", value: "01", want: "non-negative whole number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderM052Chart(t, tc.flag, tc.value)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("invalid capacity rendered: err=%v want=%q\n%s", err, tc.want, out)
			}
		})
	}
}
