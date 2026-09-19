package console

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM181OwnerReconstructionRedactsLegacyRawClaim(t *testing.T) {
	const (
		image     = "registry.example/team/credential:fixture-owner-token"
		sha       = "api-key=fixture-owner-sha"
		wantImage = "registry.example/team/credential:[REDACTED]"
		wantSHA   = "api-key=[REDACTED]"
	)

	for _, tc := range []struct {
		name string
		rec  audit.Record
	}{
		{
			name: "stored raw claim",
			rec: audit.Record{Claim: &model.ClaimScope{
				Scope: "modeled", DetectorSet: []string{"detector-z", "detector-a", "detector-z"},
				DetectorSetKnown: true, RecallCap: "detector-bounded", Note: "fixture-note",
				BrainImage: image, GitSHA: sha,
			}},
		},
		{
			name: "stored raw trace fallback",
			rec: audit.Record{DecisionTrace: &model.DecisionTraceV2{
				SchemaVersion: model.DecisionTraceSchemaV2, BrainImage: image, GitSHA: sha,
			}},
		},
	} {
			t.Run(tc.name, func(t *testing.T) {
			beforeClaim := tc.rec.Claim
			var beforeIDs []string
			if beforeClaim != nil {
				beforeIDs = append([]string(nil), beforeClaim.DetectorSet...)
			}
			beforeTrace := tc.rec.DecisionTrace
			event := ToOwnerEvent(tc.rec)
			if event.Claim.BrainImage != wantImage || event.Claim.GitSHA != wantSHA {
				t.Fatalf("owner claim not redacted: %+v", event.Claim)
			}
			ownerJSON, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(ownerJSON, []byte("fixture-owner-token")) || bytes.Contains(ownerJSON, []byte("fixture-owner-sha")) {
				t.Fatalf("serialized owner output retained synthetic secret: %s", ownerJSON)
			}
			if beforeClaim != nil {
				if beforeClaim.BrainImage != image || beforeClaim.GitSHA != sha || !reflect.DeepEqual(beforeClaim.DetectorSet, beforeIDs) {
					t.Fatal("owner reconstruction mutated stored claim")
				}
				if !reflect.DeepEqual(event.Claim.DetectorSet, []string{"detector-a", "detector-z"}) {
					t.Fatalf("owner detector set is not canonical: %v", event.Claim.DetectorSet)
				}
				beforeClaim.DetectorSet[0] = "changed"
				if !reflect.DeepEqual(event.Claim.DetectorSet, []string{"detector-a", "detector-z"}) {
					t.Fatal("owner claim aliases stored detector set")
				}
			}
			if beforeTrace != nil && (beforeTrace.BrainImage != image || beforeTrace.GitSHA != sha) {
				t.Fatal("owner reconstruction mutated stored trace")
			}
		})
	}
}

func TestM181OwnerReconstructionPreservesOrdinaryBuildMetadata(t *testing.T) {
	const image = "registry.example/team/brain:v1.2.3"
	const sha = "0123456789abcdef0123456789abcdef01234567"
	for _, rec := range []audit.Record{
		{Claim: &model.ClaimScope{BrainImage: image, GitSHA: sha}},
		{DecisionTrace: &model.DecisionTraceV2{BrainImage: image, GitSHA: sha}},
	} {
		event := ToOwnerEvent(rec)
		if event.Claim.BrainImage != image || event.Claim.GitSHA != sha {
			t.Fatalf("ordinary owner metadata changed: %+v", event.Claim)
		}
	}
}
