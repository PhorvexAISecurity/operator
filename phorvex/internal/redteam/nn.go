/*
 * Phorvex P-REDTEAM — nn.go: the RECURRENT policy/value network (a GRU + factored categorical
 * policy heads + a value head) built on the autodiff. The recurrence (GRU hidden state) is what
 * makes this an effects-only-POMDP learner: it integrates the eviction-signal history the attacker
 * observes, recovering the hidden λ-pressure the design relies on. Optimised by Adam.
 */
package redteam

import (
	"math"
	"math/rand"
)

// mat is an out×in weight matrix of Values; bias is a length-out vector.
type mat [][]*Value

func newMat(out, in int, rng *rand.Rand, scale float64) mat {
	m := make(mat, out)
	for o := 0; o < out; o++ {
		m[o] = make([]*Value, in)
		for i := 0; i < in; i++ {
			m[o][i] = newVal(rng.NormFloat64() * scale)
		}
	}
	return m
}
func newBias(out int) vec {
	b := make(vec, out)
	for o := range b {
		b[o] = newVal(0)
	}
	return b
}
func (m mat) apply(x vec) vec { // m·x
	out := make(vec, len(m))
	for o := range m {
		out[o] = dot(m[o], x)
	}
	return out
}
func addVec(a, b vec) vec {
	out := make(vec, len(a))
	for i := range a {
		out[i] = a[i].add(b[i])
	}
	return out
}

// Net is a GRU recurrent policy/value network with FACTORED categorical action heads.
type Net struct {
	in, hid     int
	headSizes   []int // factored action: one categorical head per dimension
	Wz, Wr, Wh  mat   // input->hidden gates
	Uz, Ur, Uh  mat   // hidden->hidden gates
	bz, br, bh  vec
	emb         mat // obs embedding -> input
	heads       []mat
	headB       []vec
	valW        mat
	valB        vec
	allParams   []*Value
}

// NewNet builds a recurrent net. obsDim = raw observation size; hid = GRU hidden width; headSizes =
// the factored action head cardinalities (e.g. {decoyLevels, substrates, dwellBuckets}).
func NewNet(obsDim, hid int, headSizes []int, rng *rand.Rand) *Net {
	in := hid // embedded input width == hidden for simplicity
	s := 1.0 / math.Sqrt(float64(hid))
	n := &Net{in: in, hid: hid, headSizes: headSizes,
		emb: newMat(in, obsDim, rng, s),
		Wz:  newMat(hid, in, rng, s), Wr: newMat(hid, in, rng, s), Wh: newMat(hid, in, rng, s),
		Uz: newMat(hid, hid, rng, s), Ur: newMat(hid, hid, rng, s), Uh: newMat(hid, hid, rng, s),
		bz: newBias(hid), br: newBias(hid), bh: newBias(hid),
		valW: newMat(1, hid, rng, s), valB: newBias(1),
	}
	for _, hs := range headSizes {
		n.heads = append(n.heads, newMat(hs, hid, rng, s))
		n.headB = append(n.headB, newBias(hs))
	}
	n.collect()
	return n
}

func (n *Net) collect() {
	add := func(m mat) {
		for _, row := range m {
			n.allParams = append(n.allParams, row...)
		}
	}
	addv := func(b vec) { n.allParams = append(n.allParams, b...) }
	add(n.emb)
	add(n.Wz)
	add(n.Wr)
	add(n.Wh)
	add(n.Uz)
	add(n.Ur)
	add(n.Uh)
	addv(n.bz)
	addv(n.br)
	addv(n.bh)
	for i := range n.heads {
		add(n.heads[i])
		addv(n.headB[i])
	}
	add(n.valW)
	addv(n.valB)
}

// Params returns all leaf parameters (for the optimizer / gradient checks).
func (n *Net) Params() []*Value { return n.allParams }

// CopyFrom copies another net's parameter values (PBT exploit: a weak member inherits a strong one).
func (n *Net) CopyFrom(other *Net) {
	op := other.Params()
	for i, w := range n.allParams {
		w.data = op[i].data
	}
}

// InitHidden returns a zero hidden state.
func (n *Net) InitHidden() vec {
	h := make(vec, n.hid)
	for i := range h {
		h[i] = newVal(0)
	}
	return h
}

// Forward runs one GRU step from observation obs + previous hidden h, returning the factored policy
// (one prob vector per head), the state value, and the next hidden state.
func (n *Net) Forward(obs []float64, h vec) (policy []vec, value *Value, hNext vec) {
	x := make(vec, len(obs))
	for i, o := range obs {
		x[i] = newVal(o)
	}
	xe := n.emb.apply(x) // embed
	// GRU
	z := sigVec(addVec(addVec(n.Wz.apply(xe), n.Uz.apply(h)), n.bz))
	r := sigVec(addVec(addVec(n.Wr.apply(xe), n.Ur.apply(h)), n.br))
	hc := tanhVec(addVec(addVec(n.Wh.apply(xe), n.Uh.apply(hadamard(r, h))), n.bh))
	hNext = addVec(hadamard(oneMinusVec(z), h), hadamard(z, hc))
	// heads
	for i := range n.heads {
		logits := addVec(n.heads[i].apply(hNext), n.headB[i])
		policy = append(policy, softmax(logits))
	}
	value = n.valW.apply(hNext)[0].add(n.valB[0])
	return policy, value, hNext
}

func sigVec(x vec) vec {
	o := make(vec, len(x))
	for i := range x {
		o[i] = x[i].sigmoid()
	}
	return o
}
func tanhVec(x vec) vec {
	o := make(vec, len(x))
	for i := range x {
		o[i] = x[i].tanh()
	}
	return o
}
func oneMinusVec(x vec) vec {
	o := make(vec, len(x))
	for i := range x {
		o[i] = x[i].oneMinus()
	}
	return o
}

// --- Adam optimizer over the parameter Values ---
type Adam struct {
	lr, b1, b2, eps float64
	t               int
	m, v            []float64
}

func NewAdam(p []*Value, lr float64) *Adam {
	return &Adam{lr: lr, b1: 0.9, b2: 0.999, eps: 1e-8, m: make([]float64, len(p)), v: make([]float64, len(p))}
}

// Step applies one Adam update from the current grads, with global grad-norm clipping, then zeroes.
func (o *Adam) Step(p []*Value, clip float64) {
	o.t++
	// grad-norm clip
	var nrm float64
	for _, w := range p {
		nrm += w.grad * w.grad
	}
	nrm = math.Sqrt(nrm)
	scale := 1.0
	if clip > 0 && nrm > clip {
		scale = clip / nrm
	}
	for i, w := range p {
		g := w.grad * scale
		o.m[i] = o.b1*o.m[i] + (1-o.b1)*g
		o.v[i] = o.b2*o.v[i] + (1-o.b2)*g*g
		mh := o.m[i] / (1 - math.Pow(o.b1, float64(o.t)))
		vh := o.v[i] / (1 - math.Pow(o.b2, float64(o.t)))
		w.data -= o.lr * mh / (math.Sqrt(vh) + o.eps)
	}
}

// ZeroGrad clears all parameter gradients (call before re-building the loss graph).
func ZeroGrad(p []*Value) {
	for _, w := range p {
		w.grad = 0
	}
}
