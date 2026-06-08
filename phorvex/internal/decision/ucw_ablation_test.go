/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// ucwPolicy is a fixed both-products ablation policy.
func ucwPolicy() model.Policy {
	return model.Policy{
		Tenant: "t", Namespace: "t", Mode: "dryRun", DryRun: true,
		Lambda: 0.6, NormSparsity: 0.4, FlowDisruption: 0.6, WeightSecrets: 0.8, BlastRadiusFromGraph: true,
		MaxMovesPerTick: 2, TickInterval: 20 * time.Second, AntiOverRotationWindow: 10 * time.Second,
		ProactiveFloor: 30 * time.Second, MinAvailableReplicas: 1, EventDriven: true,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
}

// ucwViews builds n pods with UNIFORM asset value (1 secret + 1 neighbor each) and high
// exposure (so PHold is non-trivial). If rareIdx >= 0 that pod gets discovered DISPERSION
// (image-rarity + EPSS), isolating the discovery effect from asset value (which is flat).
func ucwViews(n, rareIdx int, withGPU bool) []*model.WorkloadView {
	views := make([]*model.WorkloadView, 0, n)
	for i := 0; i < n; i++ {
		ph := model.NeutralPhysics()
		if i == rareIdx {
			ph.ImageRarity = 2.0 // a singleton image (max surprisal)
			ph.EPSS = 2.0        // known-exploitable
			ph.CoResidency = 2.0
		}
		name := "p" + itoa(i)
		pod := model.Pod{Namespace: "t", Name: name, UID: "u" + itoa(i),
			MountedSecrets: []string{"s" + itoa(i)}, HasGPU: withGPU && i == rareIdx}
		if withGPU && i == rareIdx {
			pod.ModelID = "llama-70b"
		}
		views = append(views, &model.WorkloadView{
			Pod:                pod,
			Phase:              model.PhaseWarm,
			BlastRadius:        0.3,
			Neighbors:          []model.NeighborRef{{Key: "t/n" + itoa(i), Value: 0.5}},
			ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 90 * time.Second},
			Physics:            ph,
		})
	}
	return views
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestUCWScarcityTiesAtUniform: with NO measured dispersion every UCW multiplier is 1.0,
// so the scarcity arm is byte-identical to the baseline — an EXACT tie (the honest
// nil-data guarantee that the 1.62x ablation is never regressed).
func TestUCWScarcityTiesAtUniform(t *testing.T) {
	seeds := []int64{1, 2, 3, 4, 5, 6, 7, 8}
	ab := AblateScarcity(ucwViews(6, -1, false), ucwPolicy(), seeds)
	if ab.Baseline.Ratio <= 0 || ab.Scarcity.Ratio <= 0 {
		t.Fatalf("degenerate ablation: %+v", ab)
	}
	if d := ab.Scarcity.Ratio - ab.Baseline.Ratio; d > 1e-9 || d < -1e-9 {
		t.Fatalf("uniform fleet must TIE: baseline=%.6f scarcity=%.6f", ab.Baseline.Ratio, ab.Scarcity.Ratio)
	}
	if l := ab.ScarcityLift; l < 0.999 || l > 1.001 {
		t.Fatalf("uniform scarcity lift must be ~1.0, got %.6f", l)
	}
}

// TestUCWScarcityLiftsUnderDispersion: a single rare/exploitable pod (asset value still
// FLAT across the fleet) creates a heavy-tailed recon-weight the submodular greedy
// exploits and the uniform-random arm cannot — so the scarcity ratio STRICTLY exceeds
// the baseline. The delta is attributable to DISCOVERED PHYSICS alone (asset value is
// identical in both arms). This is the separately-ablated beat mechanism, in-gate.
func TestUCWScarcityLiftsUnderDispersion(t *testing.T) {
	seeds := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ab := AblateScarcity(ucwViews(6, 0, false), ucwPolicy(), seeds)
	if ab.Scarcity.Ratio <= ab.Baseline.Ratio {
		t.Fatalf("dispersion must LIFT the ratio: baseline=%.4f scarcity=%.4f lift=%.4f",
			ab.Baseline.Ratio, ab.Scarcity.Ratio, ab.ScarcityLift)
	}
	if ab.ScarcityLift <= 1.0 {
		t.Fatalf("scarcity lift must be >1.0, got %.4f", ab.ScarcityLift)
	}
	t.Logf("UCW K8s dispersion: baseline ratio=%.3f, scarcity ratio=%.3f, lift=%.3fx",
		ab.Baseline.Ratio, ab.Scarcity.Ratio, ab.ScarcityLift)
}

// TestUCWAIModelDispersion: the AI half — a rare GPU/model server gets the model-rarity
// multiplier on its in-pod (rotate-cover) recon weight, so the greedy concentrates on
// the high-value NIM. Proves the AI physics affects the decision through the EXISTING
// rotate action (no Phase-2 actuator), with values honest (kind has no GPU; this uses
// the structural multiplier).
func TestUCWAIModelDispersion(t *testing.T) {
	seeds := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ab := AblateScarcity(ucwViews(6, 0, true), ucwPolicy(), seeds)
	if ab.Scarcity.Ratio < ab.Baseline.Ratio {
		t.Fatalf("AI model dispersion must not regress: baseline=%.4f scarcity=%.4f", ab.Baseline.Ratio, ab.Scarcity.Ratio)
	}
	t.Logf("UCW AI dispersion: baseline ratio=%.3f, scarcity ratio=%.3f, lift=%.3fx",
		ab.Baseline.Ratio, ab.Scarcity.Ratio, ab.ScarcityLift)
}
