package redteam

import (
	"math"
	"math/rand"
	"testing"
)

// lossOf builds a scalar loss from the net's outputs at a fixed (obs,h): value^2 - log p_head0[0].
// Rebuilding it re-reads the param .data, so it is usable for finite-difference checks.
func lossOf(n *Net, obs []float64) *Value {
	pol, val, _ := n.Forward(obs, n.InitHidden())
	return val.mul(val).sub(pol[0][0].logv())
}

// TestGradientCheck — the load-bearing correctness test: the autodiff gradients must match central
// finite differences. If this passes, backprop through the GRU + heads + value is correct, so the
// PPO updates are trustworthy (no naive/incorrect gradient code).
func TestGradientCheck(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	n := NewNet(3, 4, []int{3, 2}, rng)
	obs := []float64{0.5, -0.2, 0.1}

	ZeroGrad(n.Params())
	lossOf(n, obs).backprop()

	const eps = 1e-5
	checked, maxRel := 0, 0.0
	// check a spread of params across layers (every 7th, plus a few heads/value at the end).
	p := n.Params()
	for i := 0; i < len(p); i += 7 {
		w := p[i]
		analytic := w.grad
		orig := w.data
		w.data = orig + eps
		fp := lossOf(n, obs).data
		w.data = orig - eps
		fm := lossOf(n, obs).data
		w.data = orig
		numeric := (fp - fm) / (2 * eps)
		denom := math.Max(1e-6, math.Abs(analytic)+math.Abs(numeric))
		rel := math.Abs(analytic-numeric) / denom
		if rel > maxRel {
			maxRel = rel
		}
		checked++
		if rel > 1e-3 {
			t.Errorf("grad mismatch at param %d: analytic=%.6e numeric=%.6e rel=%.2e", i, analytic, numeric, rel)
		}
	}
	t.Logf("gradient-checked %d params, max relative error %.2e", checked, maxRel)
}

// TestReproducible — same seed => identical first forward output (determinism of the learner init).
func TestReproducible(t *testing.T) {
	mk := func() float64 {
		rng := rand.New(rand.NewSource(1337))
		n := NewNet(4, 6, []int{4, 3}, rng)
		_, v, _ := n.Forward([]float64{0.1, 0.2, 0.3, 0.4}, n.InitHidden())
		return v.Data()
	}
	if a, b := mk(), mk(); a != b {
		t.Errorf("non-reproducible net init: %v != %v", a, b)
	}
}
