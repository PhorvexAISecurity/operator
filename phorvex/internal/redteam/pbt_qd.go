/*
 * Phorvex P-REDTEAM — pbt_qd.go: POPULATION-BASED TRAINING + QUALITY-DIVERSITY (MAP-Elites).
 *
 * PBT: a population of PPO agents with perturbed hyperparameters; periodically the weak members
 * EXPLOIT a strong one (inherit weights+hypers) and EXPLORE (perturb). This is the sample-efficiency
 * + robustness win over a single learner (and over the tabular POC).
 *
 * QD (MAP-Elites): a behavior-descriptor grid that keeps the best policy PER strategy cell, so the
 * search returns DIVERSE attacks — surfacing NOVEL paths (the dispersion-steer, distinct from the
 * λ-pump) rather than collapsing to one. This is the novel/zero-day-discovery engine.
 */
package redteam

import "math/rand"

// --- PBT ---
type member struct {
	agent *Agent
	hyper Hyper
	fit   float64
}

type Population struct {
	members []*member
	obsDim  int
	rng     *rand.Rand
}

func NewPopulation(n, obsDim int, rng *rand.Rand) *Population {
	p := &Population{obsDim: obsDim, rng: rng}
	for i := 0; i < n; i++ {
		h := DefaultHyper()
		h.LR *= 0.5 + rng.Float64()          // diversify hypers
		h.EntCoef *= 0.3 + 1.4*rng.Float64() // diversify exploration pressure
		p.members = append(p.members, &member{agent: NewAgent(obsDim, h, rng), hyper: h})
	}
	return p
}

// Step trains every member one PPO iteration vs env, scores them, and does PBT exploit/explore.
func (p *Population) Step(env *Env, batch int) {
	for _, m := range p.members {
		m.agent.Train(env, batch)
		m.fit = evalAgent(m.agent, env, 8)
	}
	// rank; bottom quartile exploits a random top-quartile member + explores.
	best, worst := p.bestMember(), p.worstQuartile()
	for _, m := range worst {
		top := p.members[p.rng.Intn(maxi(1, len(p.members)/4))]
		_ = best
		m.agent.Net.CopyFrom(top.agent.Net)
		m.hyper = perturb(top.hyper, p.rng)
		m.agent.clipEps, m.agent.entCoef = m.hyper.ClipEps, m.hyper.EntCoef
		m.agent.opt = NewAdam(m.agent.Net.Params(), m.hyper.LR)
	}
}

func (p *Population) Best() *Agent { return p.bestMember().agent }
func (p *Population) bestMember() *member {
	b := p.members[0]
	for _, m := range p.members {
		if m.fit > b.fit {
			b = m
		}
	}
	return b
}
func (p *Population) worstQuartile() []*member {
	sorted := append([]*member{}, p.members...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].fit < sorted[i].fit {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	k := maxi(1, len(sorted)/4)
	return sorted[:k]
}

func perturb(h Hyper, rng *rand.Rand) Hyper {
	f := func() float64 {
		if rng.Float64() < 0.5 {
			return 0.8
		}
		return 1.25
	}
	return Hyper{LR: clampf(h.LR*f(), 1e-4, 0.1), ClipEps: clampf(h.ClipEps*f(), 0.05, 0.4), EntCoef: clampf(h.EntCoef*f(), 1e-4, 0.1)}
}

func evalAgent(a *Agent, env *Env, n int) float64 {
	s := 0.0
	for i := 0; i < n; i++ {
		s += a.EpisodeReturn(env)
	}
	return s / float64(n)
}

// --- Quality-Diversity (MAP-Elites) ---
type Elite struct {
	Return     float64
	Descriptor []float64
	Strategy   string
}
type Archive struct {
	bins int
	grid map[[2]int]Elite
}

func NewArchive(bins int) *Archive { return &Archive{bins: bins, grid: map[[2]int]Elite{}} }

// Consider places an evaluated policy into its behavior cell if it beats the cell's incumbent.
func (ar *Archive) Consider(ret float64, desc []float64) {
	cell := [2]int{binOf(desc[0], ar.bins), binOf(desc[1], ar.bins)}
	if cur, ok := ar.grid[cell]; !ok || ret > cur.Return {
		ar.grid[cell] = Elite{Return: ret, Descriptor: desc, Strategy: classify(desc)}
	}
}
func (ar *Archive) Elites() []Elite {
	var out []Elite
	for _, e := range ar.grid {
		out = append(out, e)
	}
	return out
}
func (ar *Archive) Coverage() int { return len(ar.grid) }

// classify names the strategy from the behavior descriptor [meanDecoyCount/10, steerFraction].
func classify(desc []float64) string {
	count, steer := desc[0], desc[1]
	switch {
	case count < 0.05:
		return "no-decoy / passive"
	case steer >= 0.5 && count < 0.35:
		return "DISPERSION-STEER (few high-perDollar decoys out-net the foothold)"
	case steer < 0.5 && count >= 0.4:
		return "LAMBDA-PUMP (decoy flood pumps legacy runtime lambda)"
	default:
		return "hybrid pump+steer"
	}
}

func binOf(x float64, bins int) int {
	b := int(x * float64(bins))
	if b < 0 {
		b = 0
	}
	if b >= bins {
		b = bins - 1
	}
	return b
}
func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func clampf(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}
