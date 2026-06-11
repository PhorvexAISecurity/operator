/*
 * Phorvex P-REDTEAM — the production RL adversary. autograd.go: a minimal, correct-by-construction
 * reverse-mode autodiff (micrograd-style) over scalar Values. Every op records its local gradient,
 * so backprop through the GRU/PPO is correct by construction (and gradient-checked in autograd_test).
 *
 * This is the ATTACKER's learning machinery. It contains NO Phorvex decision logic — the hard
 * boundary (no ML on Decide) is upheld: this package is imported only by cmd/redteam-rl.
 */
package redteam

import "math"

// Value is a node in the autodiff graph: a scalar with its gradient + a backward closure that
// pushes its gradient to its inputs.
type Value struct {
	data, grad float64
	backward   func()
	prev       []*Value
}

func newVal(x float64) *Value { return &Value{data: x} }

// Data/Grad accessors (tests + Adam).
func (v *Value) Data() float64 { return v.data }

func (a *Value) add(b *Value) *Value {
	out := &Value{data: a.data + b.data, prev: []*Value{a, b}}
	out.backward = func() { a.grad += out.grad; b.grad += out.grad }
	return out
}
func (a *Value) mul(b *Value) *Value {
	out := &Value{data: a.data * b.data, prev: []*Value{a, b}}
	out.backward = func() { a.grad += b.data * out.grad; b.grad += a.data * out.grad }
	return out
}
func (a *Value) sub(b *Value) *Value { return a.add(b.neg()) }
func (a *Value) neg() *Value         { return a.mulc(-1) }

// mulc multiplies by a constant (no grad to the constant).
func (a *Value) mulc(c float64) *Value {
	out := &Value{data: a.data * c, prev: []*Value{a}}
	out.backward = func() { a.grad += c * out.grad }
	return out
}
func (a *Value) addc(c float64) *Value {
	out := &Value{data: a.data + c, prev: []*Value{a}}
	out.backward = func() { a.grad += out.grad }
	return out
}
func (a *Value) tanh() *Value {
	t := math.Tanh(a.data)
	out := &Value{data: t, prev: []*Value{a}}
	out.backward = func() { a.grad += (1 - t*t) * out.grad }
	return out
}
func (a *Value) sigmoid() *Value {
	s := 1 / (1 + math.Exp(-a.data))
	out := &Value{data: s, prev: []*Value{a}}
	out.backward = func() { a.grad += s * (1 - s) * out.grad }
	return out
}
func (a *Value) exp() *Value {
	e := math.Exp(a.data)
	out := &Value{data: e, prev: []*Value{a}}
	out.backward = func() { a.grad += e * out.grad }
	return out
}
func (a *Value) logv() *Value {
	out := &Value{data: math.Log(a.data + 1e-12), prev: []*Value{a}}
	out.backward = func() { a.grad += (1 / (a.data + 1e-12)) * out.grad }
	return out
}

// oneMinus = 1 - a (used for the GRU's (1-z) gate).
func (a *Value) oneMinus() *Value { return a.mulc(-1).addc(1) }

// clamp gates the gradient: it passes only where a is inside [lo,hi] (the PPO ratio clip).
func (a *Value) clamp(lo, hi float64) *Value {
	d := a.data
	inside := d >= lo && d <= hi
	if d < lo {
		d = lo
	}
	if d > hi {
		d = hi
	}
	out := &Value{data: d, prev: []*Value{a}}
	out.backward = func() {
		if inside {
			a.grad += out.grad
		}
	}
	return out
}

// minv = min(a,b); gradient flows to the smaller operand (PPO's -min(surr1,surr2)).
func minv(a, b *Value) *Value {
	if a.data <= b.data {
		out := &Value{data: a.data, prev: []*Value{a, b}}
		out.backward = func() { a.grad += out.grad }
		return out
	}
	out := &Value{data: b.data, prev: []*Value{a, b}}
	out.backward = func() { b.grad += out.grad }
	return out
}

// backprop runs reverse-mode autodiff from this scalar (the loss).
func (root *Value) backprop() {
	var topo []*Value
	seen := map[*Value]bool{}
	var build func(*Value)
	build = func(v *Value) {
		if seen[v] {
			return
		}
		seen[v] = true
		for _, p := range v.prev {
			build(p)
		}
		topo = append(topo, v)
	}
	build(root)
	root.grad = 1
	for i := len(topo) - 1; i >= 0; i-- {
		if topo[i].backward != nil {
			topo[i].backward()
		}
	}
}

// --- small vector/matrix helpers over Values ---
type vec []*Value

func dot(w []*Value, x []*Value) *Value { // w·x
	s := newVal(0)
	for i := range w {
		s = s.add(w[i].mul(x[i]))
	}
	return s
}

// hadamard = elementwise product.
func hadamard(a, b vec) vec {
	out := make(vec, len(a))
	for i := range a {
		out[i] = a[i].mul(b[i])
	}
	return out
}

// softmax over logits (returns probabilities as Values).
func softmax(logits vec) vec {
	mx := logits[0].data
	for _, l := range logits {
		if l.data > mx {
			mx = l.data
		}
	}
	exps := make(vec, len(logits))
	sum := newVal(0)
	for i, l := range logits {
		exps[i] = l.addc(-mx).exp()
		sum = sum.add(exps[i])
	}
	out := make(vec, len(logits))
	inv := &Value{data: 1 / sum.data, prev: []*Value{sum}}
	inv.backward = func() { sum.grad += -1 / (sum.data * sum.data) * inv.grad }
	for i := range exps {
		out[i] = exps[i].mul(inv)
	}
	return out
}
