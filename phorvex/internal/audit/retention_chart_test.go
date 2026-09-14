package audit

import (
	"os/exec"
	"strings"
	"testing"
)

func renderAuditChart(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	args := []string{"template", "audit-test", "../../charts/phorvex", "--set", "phorvex.audit.enabled=true"}
	for _, set := range sets {
		flag := "--set"
		if strings.HasPrefix(set, "string:") {
			flag, set = "--set-string", strings.TrimPrefix(set, "string:")
		}
		args = append(args, flag, set)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	return string(out), err
}

func TestAuditRetentionChartDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want []string
	}{
		{name: "default", want: []string{"--audit-max-bytes=536870912", "--audit-max-backups=4"}},
		{name: "legacy segment override", sets: []string{"phorvex.audit.maxBytes=268435456"}, want: []string{"--audit-max-bytes=268435456", "--audit-max-backups=4"}},
		{name: "custom backups", sets: []string{"phorvex.audit.maxBackups=7"}, want: []string{"--audit-max-backups=7"}},
		{name: "string integer cap", sets: []string{"string:phorvex.audit.maxBytes=9223372036854775807"}, want: []string{"--audit-max-bytes=9223372036854775807"}},
		{name: "unbounded without backups", sets: []string{"phorvex.audit.maxBytes=0", "phorvex.audit.maxBackups=0"}, want: []string{"--audit-max-bytes=0", "--audit-max-backups=0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderAuditChart(t, tc.sets...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("render missing %q", want)
				}
			}
		})
	}
}

func TestAuditRetentionChartRejectsInvalidBudgets(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{name: "fractional backups", sets: []string{"phorvex.audit.maxBackups=1.5"}, want: "non-negative whole number"},
		{name: "negative backups", sets: []string{"phorvex.audit.maxBackups=-1"}, want: "non-negative whole number"},
		{name: "overflow backups", sets: []string{"string:phorvex.audit.maxBackups=9223372036854775808"}, want: "must not exceed"},
		{name: "leading-zero backups", sets: []string{"string:phorvex.audit.maxBackups=08"}, want: "non-negative whole number"},
		{name: "positive cap without backups", sets: []string{"phorvex.audit.maxBackups=0"}, want: "must be at least 1"},
		{name: "fractional bytes", sets: []string{"phorvex.audit.maxBytes=1.5"}, want: "whole number of bytes"},
		{name: "negative bytes", sets: []string{"phorvex.audit.maxBytes=-1"}, want: "whole number of bytes"},
		{name: "overflow bytes", sets: []string{"string:phorvex.audit.maxBytes=9223372036854775808"}, want: "must not exceed"},
		{name: "leading-zero bytes", sets: []string{"string:phorvex.audit.maxBytes=08"}, want: "whole number of bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderAuditChart(t, tc.sets...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("helm template err=%v output=%s", err, out)
			}
		})
	}
}

func TestAuditRetentionChartDisabledRendersNoFlags(t *testing.T) {
	args := []string{"template", "audit-test", "../../charts/phorvex", "--set", "phorvex.audit.enabled=false"}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--audit-max-") {
		t.Fatalf("disabled audit rendered retention flags:\n%s", out)
	}
}
