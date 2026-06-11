/*
 * Phorvex P-REDTEAM — cotrain.go: the CONTINUOUS CO-TRAINING loop + the HUMAN-APPROVAL promotion
 * gate. The PBT/QD population trains against the LIVE deterministic Phorvex economics (the env runs
 * cost.DualSolver — Decide stays byte-deterministic; only λ/physics re-ground as INPUTS each tick).
 * As the population learns, the attack distribution shifts -> the observation distribution shifts
 * (the non-stationary POMDP). Discovered novel paths are PROPOSED to the gate — which NEVER
 * auto-escalates: a human approves any promotion (no weight/threshold self-promotes Phorvex).
 */
package redteam

import "math/rand"

// Proposal is a discovered attack path queued for HUMAN review (never auto-applied).
type Proposal struct {
	Strategy string
	Return   float64
	Approved bool
}

// Gate is the human-approval promotion gate. AutoEscalate is hard-wired false.
type Gate struct {
	proposals []Proposal
	winBar    float64
}

func NewGate(winBar float64) *Gate { return &Gate{winBar: winBar} }

// AutoEscalate is ALWAYS false — nothing promotes without a human. (Asserted in gate_test.)
func (g *Gate) AutoEscalate() bool { return false }

// Propose queues a path IF it clears the win bar; it is NOT promoted (Approved stays false).
func (g *Gate) Propose(strategy string, ret float64) bool {
	if ret < g.winBar {
		return false
	}
	for _, p := range g.proposals {
		if p.Strategy == strategy {
			return false // already queued
		}
	}
	g.proposals = append(g.proposals, Proposal{Strategy: strategy, Return: ret})
	return true
}

// Approve is the explicit HUMAN action (the only way a proposal becomes promotable).
func (g *Gate) Approve(strategy string) {
	for i := range g.proposals {
		if g.proposals[i].Strategy == strategy {
			g.proposals[i].Approved = true
		}
	}
}
func (g *Gate) Proposals() []Proposal { return g.proposals }

// CoTrainer wires the population, the QD archive, and the gate.
type CoTrainer struct {
	Pop     *Population
	Archive *Archive
	Gate    *Gate
	env     *Env
	rng     *rand.Rand
}

func NewCoTrainer(popN, obsDim int, kind DefenderKind, winBar float64, rng *rand.Rand) *CoTrainer {
	return &CoTrainer{
		Pop:     NewPopulation(popN, obsDim, rng),
		Archive: NewArchive(8),
		Gate:    NewGate(winBar),
		env:     NewEnv(kind, rng),
		rng:     rng,
	}
}

// Generation runs one co-training round: PBT train/exploit/explore vs the deterministic defender,
// then record every member into the QD archive + propose novel winning paths to the gate. Returns
// the best greedy return this generation (the learning-curve point).
func (c *CoTrainer) Generation(batch int) float64 {
	c.Pop.Step(c.env, batch)
	bestRet := 0.0
	for _, m := range c.Pop.members {
		ret := m.agent.EpisodeReturn(c.env) // runs one greedy episode; env now holds its descriptor
		desc := c.env.Descriptor()
		c.Archive.Consider(ret, desc)
		if ret > bestRet {
			bestRet = ret
		}
		// propose the discovered strategy for HUMAN review (no auto-escalation)
		c.Gate.Propose(classify(desc), ret)
	}
	return bestRet
}
