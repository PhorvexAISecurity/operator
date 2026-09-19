package model

import (
	"reflect"
	"testing"
)

func TestM181ClaimBuildMetadataUsesTraceRedaction(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		sha       string
		wantImage string
		wantSHA   string
	}{
		{
			name:      "authorization",
			image:     "brain Authorization: Basic fixture-auth",
			sha:       "ordinary-sha",
			wantImage: "brain Authorization:[REDACTED]",
			wantSHA:   "ordinary-sha",
		},
		{
			name:      "bearer",
			image:     "brain Bearer fixture.bearer-token",
			sha:       "ordinary-sha",
			wantImage: "brain Bearer [REDACTED]",
			wantSHA:   "ordinary-sha",
		},
		{
			name:      "secret key value",
			image:     "registry.example/team/password:fixture-password",
			sha:       "token=fixture-sha-token",
			wantImage: "registry.example/team/password:[REDACTED]",
			wantSHA:   "token=[REDACTED]",
		},
		{
			name:      "unicode case folds",
			image:     "registry.example/team/paſſword:fixture-unicode",
			sha:       "api-Key=fixture-kelvin",
			wantImage: "registry.example/team/paſſword:[REDACTED]",
			wantSHA:   "api-Key=[REDACTED]",
		},
		{
			name:      "URI userinfo",
			image:     "https://fixture-user:fixture-pass@registry.example/team/brain:v1",
			sha:       "ordinary-sha",
			wantImage: "https://[REDACTED]@registry.example/team/brain:v1",
			wantSHA:   "ordinary-sha",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ids := []string{"detector-z", "detector-a", "detector-z", ""}
			original := append([]string(nil), ids...)
			claim := NewClaimScope(ids, true, tc.image, tc.sha)
			if claim.BrainImage != tc.wantImage || claim.GitSHA != tc.wantSHA {
				t.Fatalf("build metadata mismatch: image=%q sha=%q", claim.BrainImage, claim.GitSHA)
			}
			if !reflect.DeepEqual(ids, original) {
				t.Fatalf("constructor mutated detector input: got %v want %v", ids, original)
			}
			if !reflect.DeepEqual(claim.DetectorSet, []string{"detector-a", "detector-z"}) {
				t.Fatalf("detector set is not canonical: %v", claim.DetectorSet)
			}
			ids[0] = "changed"
			if !reflect.DeepEqual(claim.DetectorSet, []string{"detector-a", "detector-z"}) {
				t.Fatalf("claim aliases detector input: %v", claim.DetectorSet)
			}
		})
	}
}

func TestM181ClaimOrdinaryMetadataAndDefaultsUnchanged(t *testing.T) {
	const image = "registry.example/team/brain:v1.2.3"
	const sha = "0123456789abcdef0123456789abcdef01234567"
	ordinary := NewClaimScope([]string{"detector"}, true, image, sha)
	if ordinary.BrainImage != image || ordinary.GitSHA != sha {
		t.Fatalf("ordinary build metadata changed: %+v", ordinary)
	}

	empty := NewClaimScope(nil, false, "", "")
	if empty.BrainImage != "unavailable" || empty.GitSHA != "unavailable" {
		t.Fatalf("empty defaults changed: %+v", empty)
	}
}
