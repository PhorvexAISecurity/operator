package main

import (
	"flag"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// TestRunRefusesAnInvalidConfigurationBeforeTheCluster checks that every
// configuration problem stops the actuator before it reads the cluster or
// serves: run is given no cluster and no listener.
func TestRunRefusesAnInvalidConfigurationBeforeTheCluster(t *testing.T) {
	for _, tc := range []struct {
		name, env, value string
		args             []string
		want             string
	}{
		{name: "backend", env: "PHORVEX_ACTUATOR", value: "phoenixx", want: "invalid actuator configuration"},
		{name: "mcp image", args: []string{"--voice-mcp-approved-image=mcp:latest"}, want: "MCP image"},
		{name: "quarantine bound", args: []string{"--max-retained-quarantines-per-namespace=500"}, want: "max-retained-quarantines-per-namespace"},
		{name: "serving security", args: []string{"--serving-security-mode=plaintext-please"}, want: "serving security mode"},
		{name: "voice admission", env: "PHORVEX_VOICE_ADMISSION_ENABLED", value: "yes", want: "PHORVEX_VOICE_ADMISSION_ENABLED"},
		{name: "endpoint lease", args: []string{"--endpoint-lease-approved-source-sha256=not-a-digest"}, want: "endpoint lease"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PHORVEX_ACTUATOR", "")
			t.Setenv("PHORVEX_VOICE_ADMISSION_ENABLED", "")
			if tc.env != "" {
				t.Setenv(tc.env, tc.value)
			}
			var cfg config
			fs := flag.NewFlagSet("actuator", flag.ContinueOnError)
			cfg.trust.Register(fs)
			cfg.actuator.Register(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			err := run(t.Context(), cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}
