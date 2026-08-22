/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import "time"

// CoResidencyFloor is the safety floor from the spec. A scale below 1.0 would make the
// multiplier exceed 2.0 for an ordinary node, i.e. it would invert the term's meaning rather
// than merely mis-size it.
const CoResidencyFloor = 1.0

// ShippedCoResidencyCap mirrors platform.CoResidencyCap. It is duplicated rather than imported
// so this package stays free of the physics packages and cannot be wired into the decision
// path by accident. CoResidencyCapAgreesWithPlatform pins the two together.
const ShippedCoResidencyCap = 4.0

// NodeObservation is one node's contribution to the co-residency distribution. It is a plain
// struct, not a cluster type, so the calibration logic is testable without a snapshot and
// cannot reach back into ingest.
type NodeObservation struct {
	Name string
	// Namespaces is the count of DISTINCT namespaces with at least one pod on the node.
	Namespaces int
	// Pods is the total pod count, kept only to explain an empty node in the export.
	Pods int
	// Schedulable is the eligibility gate: an unschedulable node's tenancy is a snapshot of
	// something being drained, not a statement about how this cluster packs tenants.
	Schedulable bool
}

// X returns the node's co-residency observation, max(namespaces-1, 0) per the spec. The -1 is
// the node's own first tenant, which contributes no co-residency: one tenant alone on a node
// is not sharing it with anyone.
func (n NodeObservation) X() float64 {
	x := n.Namespaces - 1
	if x < 0 {
		x = 0
	}
	return float64(x)
}

// CoResidencyMultiplier reproduces the SHIPPED formula at an arbitrary scale:
// 1 + clamp01(X/scale), giving a multiplier in [1,2]. Reproduced here rather than imported so
// the counterfactual is computed by the same arithmetic production uses.
func CoResidencyMultiplier(x, scale float64) float64 {
	if scale <= 0 {
		return 1
	}
	r := x / scale
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	return 1 + r
}

// CoResidencyReport is the shadow result: the candidate scale, the counterfactual it implies,
// and enough raw material for someone to disagree with it.
type CoResidencyReport struct {
	Scale Scale
	// Eligible is the number of nodes that contributed observations.
	Eligible int
	// Excluded is the number of nodes skipped as unschedulable.
	Excluded int
	// Empty counts eligible nodes carrying no pods. They are legitimately X=0 and they pull
	// the distribution down, so their count is reported rather than hidden: a cluster that
	// just scaled out looks less co-resident than it will be in ten minutes.
	Empty int
	// Raw is the per-node observation, sorted by name for a stable export.
	Raw []NodeObservation
	// PercentileGrid is the distinct set of values the candidate percentile grid produces.
	// Length 1 means the grid has no resolution on this sample and cannot justify a choice.
	PercentileGrid []float64
	// ShippedAtCeiling is how many eligible nodes pin at the ceiling under the SHIPPED cap,
	// so the shadow can be compared against today rather than only against itself.
	ShippedAtCeiling int
}

// MultiplierSpread returns the number of distinct co-residency multipliers the candidate scale
// produces across the fleet, and the same under the shipped cap.
//
// This is the measure that matters, and it is not the same as saturation. The complaint in the
// ticket is that the term has "degenerated into a constant" — a scale could keep saturation low
// and still assign nearly every node the same multiplier, which buys nothing. More distinct
// values means the term is actually ranking.
func (r CoResidencyReport) MultiplierSpread() (candidate, shipped int) {
	cs, ss := map[float64]bool{}, map[float64]bool{}
	for _, n := range r.Raw {
		cs[CoResidencyMultiplier(n.X(), r.Scale.Value)] = true
		ss[CoResidencyMultiplier(n.X(), ShippedCoResidencyCap)] = true
	}
	return len(cs), len(ss)
}

// CalibrateCoResidency derives the candidate co-residency scale from the fleet's own tenancy.
//
// p is the configured percentile, minObservations the floor below which a percentile is not an
// estimate. Production is unaffected: the returned scale is a proposal.
func CalibrateCoResidency(nodes []NodeObservation, p float64, minObservations int, at time.Time) CoResidencyReport {
	r := CoResidencyReport{}
	var raw []float64
	for _, n := range nodes {
		if !n.Schedulable {
			r.Excluded++
			continue
		}
		r.Eligible++
		if n.Pods == 0 {
			r.Empty++
		}
		r.Raw = append(r.Raw, n)
		raw = append(raw, n.X())
		if CoResidencyMultiplier(n.X(), ShippedCoResidencyCap) >= 2.0 {
			r.ShippedAtCeiling++
		}
	}

	r.Scale = Measured("co_residency", raw, p, CoResidencyFloor, ShippedCoResidencyCap, minObservations, at)
	r.PercentileGrid = Identifiable(raw, []float64{0.90, 0.95, 0.975, 0.99})
	return r
}
