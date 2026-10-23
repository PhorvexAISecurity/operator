package runner

import (
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// rls_match_rate_test.go — PHVX-10c / PHORVEXSEC-98.
//
// The ticket's primary task: instrument the match rate, because Primed() answers WHETHER the
// calibrator learned and the attempt/outcome split answers WHY NOT. The three outcomes have
// completely different fixes, so collapsing them into one counter would defeat the purpose:
//
//	matched   -> a replacement was found; a real measurement trained theta.
//	censored  -> nothing became Ready in the window; trains at the censored maximum.
//	abandoned -> the original UID was still alive; the actuation never took effect at all.

// outcomeCount reads the live counter for one (tenant, outcome) pair off the real registry.
func outcomeCount(t *testing.T, tenant, outcome string) float64 {
	t.Helper()
	fams, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "phorvex_rls_rotation_observations_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			var gotTenant, gotOutcome string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "tenant":
					gotTenant = l.GetValue()
				case "outcome":
					gotOutcome = l.GetValue()
				}
			}
			if gotTenant == tenant && gotOutcome == outcome {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func gaugeValue(t *testing.T, name, tenant string) float64 {
	t.Helper()
	fams, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "tenant" && label.GetValue() == tenant && metric.GetGauge() != nil {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

func rotationView(name, uid string) *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: name, UID: uid, OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
}

// TestMatchRateSeparatesTheThreeOutcomes is the point of the ticket: the counters must distinguish
// a successful measurement from the two distinct ways it can fail.
func TestMatchRateSeparatesTheThreeOutcomes(t *testing.T) {
	startedAt := time.Unix(1_700_000_000, 0).UTC()

	t.Run("matched", func(t *testing.T) {
		const tenant = "phvx10c-matched"
		before := outcomeCount(t, tenant, "matched")
		m := &Manager{Local: &inprocess.Services{Optimizer: &observingOptimizer{}}, Log: logr.Discard()}
		v := rotationView("old", "old-uid")
		m.trackRotation(model.OwnerKey(model.OwnerKindName, tenant), tenant, v, map[string]*model.WorkloadView{"ns/old": v}, startedAt)
		m.observeReadyRotations(&sensorapi.Observation{
			Now: startedAt.Add(30 * time.Second),
			Pods: []model.Pod{{
				Namespace: "ns", Name: "new", UID: "new-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
				Ready: true, ReadyAt: startedAt.Add(20 * time.Second),
			}},
		})
		if got := outcomeCount(t, tenant, "matched") - before; got != 1 {
			t.Fatalf("matched counter moved by %v, want 1", got)
		}
	})

	t.Run("censored — nothing became Ready", func(t *testing.T) {
		const tenant = "phvx10c-censored"
		before := outcomeCount(t, tenant, "censored")
		m := &Manager{Local: &inprocess.Services{Optimizer: &observingOptimizer{}}, Log: logr.Discard()}
		v := rotationView("old", "old-uid")
		m.trackRotation(model.OwnerKey(model.OwnerKindName, tenant), tenant, v, map[string]*model.WorkloadView{"ns/old": v}, startedAt)
		m.observeReadyRotations(&sensorapi.Observation{Now: startedAt.Add(2 * cost.ReadyDelayReference)})
		if got := outcomeCount(t, tenant, "censored") - before; got != 1 {
			t.Fatalf("censored counter moved by %v, want 1", got)
		}
	})

	t.Run("abandoned — the target was never deleted", func(t *testing.T) {
		const tenant = "phvx10c-abandoned"
		before := outcomeCount(t, tenant, "abandoned")
		m := &Manager{Local: &inprocess.Services{Optimizer: &observingOptimizer{}}, Log: logr.Discard()}
		v := rotationView("old", "old-uid")
		m.trackRotation(model.OwnerKey(model.OwnerKindName, tenant), tenant, v, map[string]*model.WorkloadView{"ns/old": v}, startedAt)
		m.observeReadyRotations(&sensorapi.Observation{
			Now: startedAt.Add(2 * cost.ReadyDelayReference),
			Pods: []model.Pod{{
				Namespace: "ns", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true,
			}},
		})
		if got := outcomeCount(t, tenant, "abandoned") - before; got != 1 {
			t.Fatalf("abandoned counter moved by %v, want 1 — this is the emit-path failure, and it "+
				"must not be confused with a cost-model failure", got)
		}
		if got := outcomeCount(t, tenant, "matched"); got != 0 {
			t.Fatalf("an actuation that never took effect was counted as matched (%v)", got)
		}
	})
}

// TestOutcomeIsCountedOncePerRotationNotPerTick guards the ratio's meaning. If a still-pending
// rotation were counted on every tick that examines it, matched/total would measure tick cadence
// instead of matching success — the number would move without anything changing.
func TestOutcomeIsCountedOncePerRotationNotPerTick(t *testing.T) {
	const tenant = "phvx10c-once"
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	m := &Manager{Local: &inprocess.Services{Optimizer: &observingOptimizer{}}, Log: logr.Discard()}
	v := rotationView("old", "old-uid")
	m.trackRotation(model.OwnerKey(model.OwnerKindName, tenant), tenant, v, map[string]*model.WorkloadView{"ns/old": v}, startedAt)

	// Three ticks while the rotation is still unresolved and inside the window: no outcome yet.
	for _, d := range []time.Duration{time.Second, 10 * time.Second, 30 * time.Second} {
		m.observeReadyRotations(&sensorapi.Observation{Now: startedAt.Add(d)})
	}
	total := outcomeCount(t, tenant, "matched") + outcomeCount(t, tenant, "censored") + outcomeCount(t, tenant, "abandoned")
	if total != 0 {
		t.Fatalf("an unresolved rotation produced %v outcomes across 3 ticks; it must produce none "+
			"until it leaves the pending set", total)
	}

	// Now let it resolve.
	m.observeReadyRotations(&sensorapi.Observation{
		Now: startedAt.Add(time.Minute),
		Pods: []model.Pod{{
			Namespace: "ns", Name: "new", UID: "new-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
			Ready: true, ReadyAt: startedAt.Add(45 * time.Second),
		}},
	})
	if got := outcomeCount(t, tenant, "matched"); got != 1 {
		t.Fatalf("resolved rotation recorded %v matched outcomes, want exactly 1", got)
	}
	// And further ticks must not keep counting it.
	m.observeReadyRotations(&sensorapi.Observation{Now: startedAt.Add(2 * time.Minute)})
	if got := outcomeCount(t, tenant, "matched"); got != 1 {
		t.Fatalf("a retired rotation was counted again on a later tick (%v)", got)
	}
}

// TestRLSStateMetricsArePublished pins that the gauges the ticket asks for actually reach the
// registry when set, so "expose Primed()" cannot be quietly satisfied by an unregistered variable.
//
// Note the shape: a Prometheus *Vec with no observed label values produces no metric family at all,
// so gathering before setting anything proves nothing. The setters are called first, deliberately.
func TestRLSStateMetricsArePublished(t *testing.T) {
	metrics.SetRLSState("phvx10c-state", true, 7)
	metrics.SetRotationsPending("phvx10c-state", 3)

	want := map[string]bool{
		"phorvex_rls_primed":                      false,
		"phorvex_rls_updates_total":               false,
		"phorvex_rls_rotations_pending":           false,
		"phorvex_rls_rotation_observations_total": false,
	}
	values := map[string]float64{}
	fams, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if _, ok := want[f.GetName()]; !ok {
			continue
		}
		want[f.GetName()] = true
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "tenant" && l.GetValue() == "phvx10c-state" && m.GetGauge() != nil {
					values[f.GetName()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	var missing []string
	for name, seen := range want {
		if !seen {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("metrics not published: %s", strings.Join(missing, ", "))
	}
	for name, want := range map[string]float64{
		"phorvex_rls_primed":            1,
		"phorvex_rls_updates_total":     7,
		"phorvex_rls_rotations_pending": 3,
	} {
		if got := values[name]; got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
}

func TestPendingGaugeReturnsToZeroWhenQueueDrains(t *testing.T) {
	const tenant = "phvx10c-pending-reset"
	ce := decision.NewCoverageEngine()
	ce.ObserveRotation(tenant, rotationView("old", "old-uid"), 0.5)
	m := &Manager{
		Local: &inprocess.Services{Optimizer: ce},
		pendingRotations: map[string]pendingRotation{
			"one": {tenant: tenant},
		},
	}
	m.publishRLSMetrics()
	if got := gaugeValue(t, "phorvex_rls_rotations_pending", tenant); got != 1 {
		t.Fatalf("pending gauge = %v, want 1", got)
	}

	delete(m.pendingRotations, "one")
	m.publishRLSMetrics()
	if got := gaugeValue(t, "phorvex_rls_rotations_pending", tenant); got != 0 {
		t.Fatalf("pending gauge stayed at %v after the queue drained; stale nonzero backlog", got)
	}
}
