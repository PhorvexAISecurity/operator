package buildinfo

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCurrentPrefersExplicitExactBuildIdentity(t *testing.T) {
	t.Setenv("PHORVEX_BRAIN_IMAGE", "registry/phorvex:sha-123")
	t.Setenv("PHORVEX_GIT_SHA", "1234567890abcdef")
	got := Current()
	if got.BrainImage != "registry/phorvex:sha-123" || got.GitSHA != "1234567890abcdef" || got.Version == "" {
		t.Fatalf("build identity = %+v", got)
	}
}

func TestEmbeddedVersionIdentityCannotBeOverriddenByEnvironment(t *testing.T) {
	oldSHA, oldVersion := linkedGitSHA, linkedVersion
	t.Cleanup(func() { linkedGitSHA, linkedVersion = oldSHA, oldVersion })
	linkedGitSHA = "0123456789abcdef0123456789abcdef01234567"
	linkedVersion = "1.2.3"
	t.Setenv("PHORVEX_GIT_SHA", "ffffffffffffffffffffffffffffffffffffffff")
	var output bytes.Buffer
	if err := WriteVersion(&output, "sensor"); err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"service": "sensor", "version": "1.2.3", "gitSHA": linkedGitSHA}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("version output %s = %q, want %q: %s", key, got[key], value, output.Bytes())
		}
	}
}

func TestCurrentMakesUnavailableImageExplicit(t *testing.T) {
	t.Setenv("PHORVEX_BRAIN_IMAGE", "")
	got := Current()
	if got.BrainImage != NotAvailable || got.GitSHA == "" {
		t.Fatalf("honest absence/build identity = %+v", got)
	}
}
