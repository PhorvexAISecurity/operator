package redteam

import (
	"math"
	"math/rand"
	"testing"
)

// steerSurvival reports how many of n ticks the steer keeps the foothold alive vs a given defender.
func steerSurvival(kind DefenderKind, n int) int {
	env := NewEnv(kind, rand.New(rand.NewSource(1)))
	env.Reset()
	survived := 0
	for i := 0; i < n && !env.Done(); i++ {
		if _, done := env.Step([]int{1, 1, 0}); !done { // 2 steer-grade decoys
			survived++
		}
	}
	return survived
}

// TestDispersionSteerVulnAndFix — the discovered vuln AND the gated fix, both proven in the env:
//   - vs λ-fix-only Phorvex the dispersion-steer WORKS (the foothold survives) — the real vuln.
//   - vs the SHIPPED Phorvex (λ-fix + provenance steer-fix) it is NEUTRALIZED — the decoy can no
//     longer crowd the genuinely-due foothold out of the slot, so the foothold is rotated.
func TestDispersionSteerVulnAndFix(t *testing.T) {
	vuln := steerSurvival(DefPhorvexLambdaOnly, 10)
	fixed := steerSurvival(DefPhorvexFixed, 10)
	if vuln < 8 {
		t.Errorf("the dispersion-steer should WORK vs λ-fix-only Phorvex (survived %d/10) — the vuln", vuln)
	}
	if fixed > 2 {
		t.Errorf("the steer-fix should NEUTRALIZE the dispersion-steer vs SHIPPED Phorvex (survived %d/10)", fixed)
	}
	t.Logf("steer survival: λ-fix-only=%d/10 (vuln) -> SHIPPED=%d/10 (neutralized)", vuln, fixed)
}

// TestPOMDPRandomIgnoresDecoys — vs the random defender, the attacker's decoys do NOT change the
// rotation (no structure to exploit). Steer and no-decoy give statistically the same survival.
func TestPOMDPRandomIgnoresDecoys(t *testing.T) {
	dwell := func(action []int, seed int64) float64 {
		env := NewEnv(DefRandom, rand.New(rand.NewSource(seed)))
		total := 0.0
		for ep := 0; ep < 200; ep++ {
			env.Reset()
			for !env.Done() {
				env.Step(action)
			}
			total += float64(env.tick)
		}
		return total / 200
	}
	steer := dwell([]int{1, 1, 0}, 7)
	none := dwell([]int{0, 0, 0}, 7)
	if math.Abs(steer-none) > 1.5 {
		t.Errorf("vs random the decoys must NOT help (steer dwell %.2f vs none %.2f differ too much)", steer, none)
	}
}

// TestRewardShaped — the reward is computed from the real per-tick outcome (dwell + decoy cost +
// eviction penalty), never a constant: a rotation tick costs the eviction penalty; survival pays +1.
func TestRewardShaped(t *testing.T) {
	env := NewEnv(DefPhorvexLambdaOnly, rand.New(rand.NewSource(2)))
	env.Reset()
	rSurvive, _ := env.Step([]int{1, 1, 0}) // steer vs λ-fix-only => survives => positive
	env.Reset()
	rEvict, _ := env.Step([]int{0, 0, 0}) // no decoy => rotated => eviction penalty => negative
	if !(rSurvive > 0 && rEvict < 0) {
		t.Errorf("reward not shaped from the real outcome: survive=%.2f (want>0) evict=%.2f (want<0)", rSurvive, rEvict)
	}
}

// TestGateNoAutoEscalation — the human-approval gate NEVER auto-escalates; Propose queues but does
// not approve; only the explicit human Approve flips it.
func TestGateNoAutoEscalation(t *testing.T) {
	g := NewGate(5.0)
	if g.AutoEscalate() {
		t.Fatal("AutoEscalate must be hard-wired false")
	}
	g.Propose("DISPERSION-STEER", 35.0) // clears the bar
	g.Propose("weak-path", 1.0)         // below the bar => not queued
	if len(g.Proposals()) != 1 {
		t.Fatalf("only above-bar paths queue; got %d", len(g.Proposals()))
	}
	if g.Proposals()[0].Approved {
		t.Error("a proposed path must NOT be auto-approved")
	}
	g.Approve("DISPERSION-STEER") // the human action
	if !g.Proposals()[0].Approved {
		t.Error("explicit human Approve must promote")
	}
}

func meanReturn(a *Agent, env *Env, n int) float64 {
	s := 0.0
	for i := 0; i < n; i++ {
		s += a.EpisodeReturn(env)
	}
	return s / float64(n)
}

// TestLearnerLearns — integration: a short Recurrent-PPO run measurably IMPROVES the agent's return
// vs an EXPLOITABLE Phorvex (λ-fix-only, where the dispersion-steer path is still open). A real
// learning assertion (the learner is real and discovers the open path).
func TestLearnerLearns(t *testing.T) {
	rng := rand.New(rand.NewSource(1337))
	env := NewEnv(DefPhorvexLambdaOnly, rng)
	a := NewAgent(len(env.Obs()), DefaultHyper(), rng)
	start := meanReturn(a, env, 6)
	for i := 0; i < 8; i++ {
		a.Train(env, 8)
	}
	end := meanReturn(a, env, 6)
	if end <= start+5 {
		t.Errorf("the learner did not measurably improve vs the exploitable defender: %.1f -> %.1f", start, end)
	}
	t.Logf("learner climbed %.1f -> %.1f", start, end)
}

// TestSteerFixNeutralizes — the gated steer-fix WORKS: trained against the SHIPPED Phorvex (λ-fix +
// provenance steer-fix), the production RL CANNOT climb (both the λ-pump and the dispersion-steer
// are closed). It stays near the undefended baseline — the proof the fix defeats the discovered vuln.
func TestSteerFixNeutralizes(t *testing.T) {
	rng := rand.New(rand.NewSource(1337))
	env := NewEnv(DefPhorvexFixed, rng)
	a := NewAgent(len(env.Obs()), DefaultHyper(), rng)
	for i := 0; i < 12; i++ {
		a.Train(env, 8)
	}
	end := meanReturn(a, env, 8)
	if end > 12 {
		t.Errorf("the steer-fix failed: the RL still climbed vs SHIPPED Phorvex (return %.1f — should be near baseline)", end)
	}
	t.Logf("vs SHIPPED Phorvex the RL is held to %.1f (neutralized — no exploitable path)", end)
}

// TestReproducibleTraining — same seed => identical learning outcome (determinism of the learner).
func TestReproducibleTraining(t *testing.T) {
	run := func() float64 {
		rng := rand.New(rand.NewSource(99))
		env := NewEnv(DefPhorvexFixed, rng)
		a := NewAgent(len(env.Obs()), DefaultHyper(), rng)
		for i := 0; i < 4; i++ {
			a.Train(env, 6)
		}
		return a.EpisodeReturn(env)
	}
	if x, y := run(), run(); x != y {
		t.Errorf("non-reproducible training under fixed seed: %v != %v", x, y)
	}
}
