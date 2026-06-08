package mocks

import (
	"context"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// TamperedMarker is the proof string a tampered/poisoned image's injected layer
// writes when it runs. The supply-chain oracle checks for this marker.
const TamperedMarker = "R6TH-TAMPERED-IMAGE-PAYLOAD-RAN"

// MockRegistry stands in for an OCI registry that serves a "tampered" image. On a
// kind node we do not run a real registry daemon for the smoke; instead the
// "tampered image" is MODELED faithfully as a busybox pod whose entrypoint writes
// the tampered marker — i.e. the injected malicious layer's behavior — proving
// the poisoned payload executed. The MockServer here is the registry control
// endpoint placeholder (serves the image manifest digest) so the kill-chain has a
// registry to "pull" from in its provenance/logs.
type MockRegistry struct {
	*MockServer
	// PoisonedImageRef is the logical reference the scenario "pulls".
	PoisonedImageRef string
}

// DeployRegistry deploys the mock registry control endpoint and returns the
// poisoned image reference the supply-chain scenario uses.
func DeployRegistry(ctx context.Context, env *core.Env) (*MockRegistry, error) {
	body := `{"name":"r6th/poisoned-app","tags":["latest"],"digest":"sha256:deadbeefr6thmockpoisoned"}`
	srv, err := deployServer(ctx, env, "mock-registry", 8083, httpResponderScript(body), map[string]string{"r6th.io/mock": "registry"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock registry up at %s:%d (serves a poisoned image manifest stand-in)", srv.ClusterDNS, srv.Port)
	return &MockRegistry{MockServer: srv, PoisonedImageRef: srv.ClusterDNS + ":8083/r6th/poisoned-app:latest"}, nil
}

// PoisonedImageCommand returns the busybox command that FAITHFULLY emulates a
// poisoned image entrypoint: it writes the tampered marker to a shared path and
// then idles. Using busybox+this command is the containment-safe stand-in for
// "pull and run the tampered image" — the injected layer's behavior runs, which
// is exactly the oracle.
func PoisonedImageCommand(markerPath string) []string {
	return []string{"sh", "-c", "echo " + TamperedMarker + " > " + markerPath + "; while true; do sleep 3600; done"}
}
