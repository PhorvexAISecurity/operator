package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

func TestNATSOneUseFixtureArmGuardPrecedesKubernetesClientBuild(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist-kubeconfig")
	base := config.TargetConfig{Kubeconfig: missing, Context: "missing-context"}

	withFixture := base
	withFixture.NATSJetStreamFixture = &config.NATSJetStreamFixtureConfig{}
	for _, tc := range []struct {
		name               string
		negative, adaptive bool
	}{
		{name: "negative control", negative: true},
		{name: "adaptive arm", adaptive: true},
		{name: "both extra arms", negative: true, adaptive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(context.Background(), withFixture, false, tc.negative, tc.adaptive, false)
			if err == nil || !strings.Contains(err.Error(), "-negative-control=false and -adaptive=false") || strings.Contains(err.Error(), missing) {
				t.Fatalf("fixture guard did not refuse before client build: %v", err)
			}
		})
	}

	// Legacy configs retain both default-enabled runner arms and proceed to the
	// existing client boundary. The nonexistent kubeconfig makes that boundary
	// observable without contacting a cluster.
	err := run(context.Background(), base, false, true, true, false)
	if err == nil || strings.Contains(err.Error(), "-negative-control=false and -adaptive=false") {
		t.Fatalf("nil fixture was incorrectly subject to one-use guard: %v", err)
	}
}
