package recon

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// scarcity_uniform_test.go — PHVX-70 / PHORVEXSEC-126.
//
// ucw.go's doc comment claims the scarcity scalar is applied "UNIFORMLY to every fact of the asset",
// and that uniformity is what makes its EMR argument sound: a factor common to all of an asset's
// facts preserves the within-asset ordering and only sharpens the cross-asset one. It was applied
// before the AI facts were appended, so it reached six facts and skipped the rest.

func gpuView() *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m",
			MountedSecrets: []string{"creds"},
		},
		Physics: model.PhysicsWitness{
			ImageRarity: 2.0, EPSS: 1.0, CoResidency: 2.0, ModelRarity: 1.0, // product 4.0
		},
	}
}

func factsByKind(fs []Fact) map[string]float64 {
	out := map[string]float64{}
	for _, f := range fs {
		out[f.Kind] = f.Weight
	}
	return out
}

// TestScarcityScalesEveryFactUniformly is the regression. The ratio between an AI fact and a base
// fact on the SAME asset must not depend on the scarcity scalar — that is what "uniform" means.
func TestScarcityScalesEveryFactUniformly(t *testing.T) {
	fctx := FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true}

	neutral := gpuView()
	neutral.Physics = model.NeutralPhysics() // every multiplier 1.0 => s == 1.0
	flat := factsByKind(ucwRecon{}.AssetFacts(neutral, fctx).Facts)

	lifted := factsByKind(ucwRecon{}.AssetFacts(gpuView(), fctx).Facts)

	base, ai := FactPodIdentity, FactEndpointPath
	if flat[base] == 0 || flat[ai] == 0 {
		t.Fatalf("fixture produced no %s or %s fact: %v", base, ai, flat)
	}

	// Each fact must be lifted by the SAME factor.
	baseLift := lifted[base] / flat[base]
	aiLift := lifted[ai] / flat[ai]
	if math.Abs(baseLift-aiLift) > 1e-9 {
		t.Fatalf("scarcity was not applied uniformly: the base fact %q was lifted %.4fx but the AI "+
			"fact %q only %.4fx. A base fact then outranks an AI fact on the same asset by %.2fx, "+
			"steering the engine to generic moves on exactly the workloads the AI facts exist for.",
			base, baseLift, ai, aiLift, baseLift/aiLift)
	}
	if math.Abs(baseLift-4.0) > 1e-9 {
		t.Errorf("fixture should lift by the full 4.0 product; got %.4f", baseLift)
	}
}

// TestScarcityPreservesWithinAssetOrdering states the property the uniformity exists to protect.
//
// It compares only facts whose weight is the plain `base * urg` form. Three facts deliberately carry
// a physics term of their OWN — modelFingerprint multiplies ModelRarity and gpuColocation multiplies
// CoResidency (ucw.go) — so their ratio to other facts is SUPPOSED to move with physics. An earlier
// version of this test compared every pair and failed on exactly that, correctly: the assertion was
// wrong, not the code.
func TestScarcityPreservesWithinAssetOrdering(t *testing.T) {
	fctx := FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true}
	neutral := gpuView()
	neutral.Physics = model.NeutralPhysics()

	flat := factsByKind(ucwRecon{}.AssetFacts(neutral, fctx).Facts)
	lifted := factsByKind(ucwRecon{}.AssetFacts(gpuView(), fctx).Facts)

	// Facts weighted purely as base*urg, i.e. carrying no physics term of their own.
	plain := []string{FactEndpointPath, FactSideChannel, FactInflightRequests, FactGuardrailBypass, FactPodIdentity}
	for _, a := range plain {
		for _, b := range plain {
			if a == b || flat[a] == 0 || flat[b] == 0 {
				continue
			}
			flatRatio := flat[a] / flat[b]
			liftRatio := lifted[a] / lifted[b]
			if math.Abs(flatRatio-liftRatio) > 1e-9 {
				t.Fatalf("dispersion changed the within-asset ratio of %q to %q: %.6f -> %.6f. The "+
					"scarcity scalar is supposed to sharpen only the CROSS-asset ordering.",
					a, b, flatRatio, liftRatio)
			}
		}
	}
}
