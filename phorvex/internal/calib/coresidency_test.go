/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/platform"
)

func at0() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

// liveFleet is the EKS cluster as measured on 2026-08-19 — real node names, real namespace and
// pod counts, all five nodes Ready and schedulable, 71 running pods. Kept as the fixture because
// the whole ticket is an argument about THIS distribution; a synthetic one would let the argument
// drift away from the cluster it is about.
func liveFleet() []NodeObservation {
	return []NodeObservation{
		{Name: "ip-172-27-12-138", Namespaces: 2, Pods: 6, Schedulable: true},
		{Name: "ip-172-27-12-51", Namespaces: 4, Pods: 9, Schedulable: true},
		{Name: "ip-172-27-12-137", Namespaces: 5, Pods: 13, Schedulable: true},
		{Name: "ip-172-27-11-153", Namespaces: 8, Pods: 17, Schedulable: true},
		{Name: "ip-172-27-12-134", Namespaces: 9, Pods: 26, Schedulable: true},
	}
}

// The shipped cap is 4.0, so any node with 5+ namespaces pins the multiplier at 2.0. On the live
// fleet that is three of five nodes — the "effectively constant" state the ticket describes,
// reproduced here from the formula rather than asserted.
func TestShippedCapSaturatesTheLiveFleet(t *testing.T) {
	r := CalibrateCoResidency(liveFleet(), 0.95, 1, at0())
	if r.ShippedAtCeiling != 3 {
		t.Fatalf("nodes pinned under the shipped cap = %d, want 3", r.ShippedAtCeiling)
	}
	_, shipped := r.MultiplierSpread()
	if shipped != 3 {
		t.Fatalf("the shipped cap produces %d distinct multipliers across 5 nodes, want 3", shipped)
	}
}

// The candidate scale must widen the term, not just move the ceiling. More distinct multipliers
// is the property that means co-residency is ranking nodes again instead of labelling most of
// them identically.
func TestCalibratedScaleWidensTheMultiplier(t *testing.T) {
	r := CalibrateCoResidency(liveFleet(), 0.95, 1, at0())

	if !r.Scale.IsMeasured() {
		t.Fatalf("scale reported %q with reason %q, want a measured scale", r.Scale.Source, r.Scale.Reason)
	}
	if r.Scale.Value != 8 {
		t.Fatalf("P95 of X_node=[1,3,4,7,8] = %v, want 8", r.Scale.Value)
	}
	cand, shipped := r.MultiplierSpread()
	if cand <= shipped {
		t.Fatalf("candidate produces %d distinct multipliers vs shipped %d — the recalibration bought no discrimination", cand, shipped)
	}
	if cand != 5 {
		t.Errorf("candidate distinct multipliers = %d, want 5 (one per node)", cand)
	}
}

// The saturation alarm the ticket asks for, at the threshold the math owner set (>10%).
//
// It fires on the live fleet BOTH before and after co-residency is recalibrated, and that is the
// finding, not a bug in the test: 1 of 5 nodes still sits at the ceiling under P95, which is 20%.
// Recalibrating this one scale is not sufficient to clear the invariant.
func TestSaturationAlarmStillFiresAfterCoResidencyAlone(t *testing.T) {
	r := CalibrateCoResidency(liveFleet(), 0.95, 1, at0())
	const threshold = 0.10

	if !r.Scale.Saturated(threshold) {
		t.Fatalf("at-ceiling ratio %.4f did not trip the %.0f%% alarm; the ticket's premise is that it should",
			r.Scale.Clip.AtCeilingRatio(), threshold*100)
	}
	if got := r.Scale.Clip.AtCeilingRatio(); math.Abs(got-0.20) > 1e-9 {
		t.Errorf("at-ceiling ratio = %.4f, want 0.20", got)
	}
}

// A percentile over a handful of nodes is a number but not an estimate. Below the minimum the
// scale must come back as the shipped constant with a stated reason, never as a confident value.
func TestTooFewNodesFallsBackWithAReason(t *testing.T) {
	r := CalibrateCoResidency(liveFleet(), 0.95, 20, at0())
	if r.Scale.IsMeasured() {
		t.Fatal("5 nodes produced a measured scale against a minimum of 20")
	}
	if r.Scale.Value != ShippedCoResidencyCap {
		t.Errorf("fallback value = %v, want the shipped cap %v", r.Scale.Value, ShippedCoResidencyCap)
	}
	if r.Scale.Reason == "" {
		t.Error("fallback carries no reason — an unexplained fallback is indistinguishable from a measurement that happened to agree")
	}
}

// Unschedulable nodes are excluded: a draining node's tenancy describes an event, not how the
// cluster packs tenants.
func TestUnschedulableNodesAreExcluded(t *testing.T) {
	nodes := append(liveFleet(), NodeObservation{Name: "drain", Namespaces: 40, Pods: 90, Schedulable: false})
	r := CalibrateCoResidency(nodes, 0.95, 1, at0())
	if r.Excluded != 1 {
		t.Fatalf("excluded = %d, want 1", r.Excluded)
	}
	if r.Scale.Value != 8 {
		t.Fatalf("scale = %v, want 8 — the unschedulable node's 40 namespaces leaked into the distribution", r.Scale.Value)
	}
}

// An empty schedulable node is a real X=0 observation and must be counted. Dropping it would
// bias the fleet to look more tenant-dense than it is — the direction that hides the problem.
func TestEmptyNodesCountAsZeroAndAreReported(t *testing.T) {
	nodes := append(liveFleet(), NodeObservation{Name: "fresh", Namespaces: 0, Pods: 0, Schedulable: true})
	r := CalibrateCoResidency(nodes, 0.95, 1, at0())
	if r.Empty != 1 {
		t.Fatalf("empty = %d, want 1", r.Empty)
	}
	if r.Eligible != 6 {
		t.Fatalf("eligible = %d, want 6", r.Eligible)
	}
}

// The floor is enforced, not warned about: a scale below 1.0 makes X/scale exceed 1 for an
// ordinary node, inverting the term rather than mis-sizing it.
func TestScaleIsFlooredAndSaysSo(t *testing.T) {
	flat := []NodeObservation{
		{Name: "a", Namespaces: 1, Pods: 1, Schedulable: true},
		{Name: "b", Namespaces: 1, Pods: 1, Schedulable: true},
	}
	r := CalibrateCoResidency(flat, 0.95, 1, at0())
	if r.Scale.Value != CoResidencyFloor {
		t.Fatalf("scale = %v, want the floor %v", r.Scale.Value, CoResidencyFloor)
	}
	if !r.Scale.FlooredUp {
		t.Error("FlooredUp is false — the measurement disagreed with the model's premise and that must be visible")
	}
}

// The duplicated constant must not drift from the one production uses.
func TestCoResidencyCapAgreesWithPlatform(t *testing.T) {
	if ShippedCoResidencyCap != platform.CoResidencyCap {
		t.Fatalf("calib says the shipped cap is %v, platform says %v — the shadow is comparing against the wrong baseline",
			ShippedCoResidencyCap, platform.CoResidencyCap)
	}
}

// The counterfactual must be computed by the same arithmetic production uses, or the shadow is
// measuring a formula nobody runs.
func TestMultiplierMatchesTheShippedFormula(t *testing.T) {
	for _, ns := range []int{1, 2, 5, 9, 40} {
		x := float64(ns - 1)
		want := 1 + math.Min(math.Max(x/platform.CoResidencyCap, 0), 1)
		if got := CoResidencyMultiplier(x, ShippedCoResidencyCap); math.Abs(got-want) > 1e-12 {
			t.Errorf("namespaces=%d: calib %v vs shipped formula %v", ns, got, want)
		}
	}
}
