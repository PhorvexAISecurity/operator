/*
 * Phorvex P-REDTEAM — ppo.go: RECURRENT PPO. Rolls out the GRU policy in the POMDP, computes GAE
 * advantages, and updates with the clipped surrogate + value loss + entropy bonus via BPTT (the
 * trajectory is re-forwarded so gradients flow through the GRU's time recurrence). Adam, grad-norm
 * clip, advantage normalisation — production-grade, gradient-checked underneath (nn_test).
 */
package redteam

import (
	"math"
	"math/rand"
)

type Agent struct {
	Net     *Net
	opt     *Adam
	clipEps float64
	vfCoef  float64
	entCoef float64
	gamma   float64
	lam     float64
	epochs  int
	rng     *rand.Rand
}

// Hyper holds the PBT-perturbable hyperparameters.
type Hyper struct {
	LR      float64
	ClipEps float64
	EntCoef float64
}

func DefaultHyper() Hyper { return Hyper{LR: 0.01, ClipEps: 0.2, EntCoef: 0.01} }

func NewAgent(obsDim int, h Hyper, rng *rand.Rand) *Agent {
	net := NewNet(obsDim, 12, ActionDims(), rng)
	return &Agent{
		Net: net, opt: NewAdam(net.Params(), h.LR),
		clipEps: h.ClipEps, vfCoef: 0.5, entCoef: h.EntCoef, gamma: 0.97, lam: 0.95, epochs: 4, rng: rng,
	}
}

type transition struct {
	obs    []float64
	action []int
	logp   float64
	value  float64
	reward float64
}

// rollout runs one episode (data collection; the policy graph is discarded, only scalars kept).
func (a *Agent) rollout(env *Env) []transition {
	env.Reset()
	h := a.Net.InitHidden()
	var tr []transition
	for !env.Done() {
		obs := env.Obs()
		pol, val, hn := a.Net.Forward(obs, h)
		act, lp := sampleFactored(pol, a.rng)
		r, _ := env.Step(act)
		tr = append(tr, transition{obs: obs, action: act, logp: lp, value: val.Data(), reward: r})
		h = detach(hn)
	}
	return tr
}

// EpisodeReturn runs a GREEDY (argmax) episode and returns its total reward (for evaluation curves).
func (a *Agent) EpisodeReturn(env *Env) float64 {
	env.Reset()
	h := a.Net.InitHidden()
	total := 0.0
	for !env.Done() {
		pol, _, hn := a.Net.Forward(env.Obs(), h)
		act := make([]int, len(pol))
		for k := range pol {
			act[k] = argmaxProb(pol[k])
		}
		r, _ := env.Step(act)
		total += r
		h = detach(hn)
	}
	return total
}

// Train runs one PPO iteration: collect `batch` episodes, compute GAE, and do `epochs` BPTT updates.
func (a *Agent) Train(env *Env, batch int) {
	var trajs [][]transition
	for b := 0; b < batch; b++ {
		trajs = append(trajs, a.rollout(env))
	}
	// GAE + normalised advantages per trajectory.
	type prepped struct {
		tr   []transition
		adv  []float64
		ret  []float64
	}
	var data []prepped
	var allAdv []float64
	for _, tr := range trajs {
		adv := make([]float64, len(tr))
		ret := make([]float64, len(tr))
		gae := 0.0
		for t := len(tr) - 1; t >= 0; t-- {
			nextV := 0.0
			if t+1 < len(tr) {
				nextV = tr[t+1].value
			}
			delta := tr[t].reward + a.gamma*nextV - tr[t].value
			gae = delta + a.gamma*a.lam*gae
			adv[t] = gae
			ret[t] = gae + tr[t].value
			allAdv = append(allAdv, gae)
		}
		data = append(data, prepped{tr, adv, ret})
	}
	mean, std := meanStd(allAdv)
	for i := range data {
		for t := range data[i].adv {
			data[i].adv[t] = (data[i].adv[t] - mean) / (std + 1e-8)
		}
	}
	// PPO epochs (BPTT over each trajectory).
	for e := 0; e < a.epochs; e++ {
		for _, d := range data {
			ZeroGrad(a.Net.Params())
			loss := newVal(0)
			h := a.Net.InitHidden()
			for t, s := range d.tr {
				pol, val, hn := a.Net.Forward(s.obs, h)
				newLogp := factoredLogp(pol, s.action)
				ratio := newLogp.addc(-s.logp).exp()
				adv := d.adv[t]
				surr1 := ratio.mulc(adv)
				surr2 := ratio.clamp(1-a.clipEps, 1+a.clipEps).mulc(adv)
				policyLoss := minv(surr1, surr2).neg() // -min(surr1,surr2)
				vDiff := val.addc(-d.ret[t])
				valueLoss := vDiff.mul(vDiff).mulc(a.vfCoef)
				ent := entropy(pol).mulc(a.entCoef)
				loss = loss.add(policyLoss).add(valueLoss).sub(ent)
				h = hn
			}
			loss.mulc(1.0 / float64(len(d.tr))).backprop()
			a.opt.Step(a.Net.Params(), 0.5)
		}
	}
}

// --- sampling / log-prob / entropy over the FACTORED categorical policy ---
func sampleFactored(pol []vec, rng *rand.Rand) ([]int, float64) {
	act := make([]int, len(pol))
	lp := 0.0
	for k, head := range pol {
		i := sampleCat(head, rng)
		act[k] = i
		lp += math.Log(head[i].data + 1e-12)
	}
	return act, lp
}
func sampleCat(p vec, rng *rand.Rand) int {
	r := rng.Float64()
	c := 0.0
	for i := range p {
		c += p[i].data
		if r <= c {
			return i
		}
	}
	return len(p) - 1
}
func factoredLogp(pol []vec, action []int) *Value {
	s := newVal(0)
	for k, head := range pol {
		s = s.add(head[action[k]].logv())
	}
	return s
}
func entropy(pol []vec) *Value {
	s := newVal(0)
	for _, head := range pol {
		for _, p := range head {
			s = s.sub(p.mul(p.logv()))
		}
	}
	return s
}
func argmaxProb(p vec) int {
	bi, bv := 0, p[0].data
	for i := range p {
		if p[i].data > bv {
			bv, bi = p[i].data, i
		}
	}
	return bi
}

// detach returns a fresh leaf copy of a hidden vector (cuts the graph between rollout steps).
func detach(h vec) vec {
	out := make(vec, len(h))
	for i := range h {
		out[i] = newVal(h[i].data)
	}
	return out
}
func meanStd(xs []float64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 1
	}
	m := 0.0
	for _, x := range xs {
		m += x
	}
	m /= float64(len(xs))
	v := 0.0
	for _, x := range xs {
		v += (x - m) * (x - m)
	}
	return m, math.Sqrt(v / float64(len(xs)))
}
