package buildinfo

import "testing"

func TestCurrentPrefersExplicitExactBuildIdentity(t *testing.T) {
	t.Setenv("PHORVEX_BRAIN_IMAGE", "registry/phorvex:sha-123")
	t.Setenv("PHORVEX_GIT_SHA", "1234567890abcdef")
	got := Current()
	if got.BrainImage != "registry/phorvex:sha-123" || got.GitSHA != "1234567890abcdef" {
		t.Fatalf("build identity = %+v", got)
	}
}

func TestCurrentMakesUnavailableImageExplicit(t *testing.T) {
	t.Setenv("PHORVEX_BRAIN_IMAGE", "")
	got := Current()
	if got.BrainImage != NotAvailable || got.GitSHA == "" {
		t.Fatalf("honest absence/build identity = %+v", got)
	}
}
