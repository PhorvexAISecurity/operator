package actionset

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestM153FactCloneOwnsNestedSteeringReferences(t *testing.T) {
	in := []recon.Fact{{Kind: recon.FactSession, SteeredBy: &model.VectorSteeringAttribution{
		RuleType: model.AttackVectorKV, AppliedMultiplier: 3,
		Events: []model.VectorSteeringEvent{{EventName: "original", EventUID: "uid"}},
	}}}
	out := cloneFacts(in)
	out[0].SteeredBy.RuleType = "changed"
	out[0].SteeredBy.Events[0].EventName = "changed"
	if in[0].SteeredBy.RuleType != model.AttackVectorKV || in[0].SteeredBy.Events[0].EventName != "original" {
		t.Fatalf("nested steering aliases caller state: %+v", in)
	}
}
