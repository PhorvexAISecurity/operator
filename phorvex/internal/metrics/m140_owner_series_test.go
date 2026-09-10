/*
 * M-140 telemetry regressions. Two policies may share a spec.tenant display name; the legacy
 * per-tenant series cannot describe two economic units, and per-pod series must not be
 * deleted by another owner's tick.
 */

package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/internal/model"
)

func gaugeValue(t *testing.T, g *dto.MetricFamily, labels map[string]string) (float64, bool) {
	t.Helper()
	if g == nil {
		return 0, false
	}
next:
	for _, m := range g.GetMetric() {
		for k, want := range labels {
			found := false
			for _, lp := range m.GetLabel() {
				if lp.GetName() == k && lp.GetValue() == want {
					found = true
					break
				}
			}
			if !found {
				continue next
			}
		}
		return m.GetGauge().GetValue(), true
	}
	return 0, false
}

func family(t *testing.T, name string) *dto.MetricFamily {
	t.Helper()
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

func m140Decision(pod string, lambda float64) model.Decision {
	return model.Decision{Namespace: "ns", Pod: pod, Lambda: lambda}
}

// Two owners sharing one display name must each publish their own lambda, and the legacy
// per-tenant series must be WITHDRAWN rather than left serving whichever policy ticked last.
func TestM140_CollisionWithdrawsLegacyTenantSeriesAndKeepsPerOwner(t *testing.T) {
	const tenant = "m140-collision"
	// Uniqueness first: the legacy series is published.
	SetTenantOwnerCount(tenant, 1)
	PublishTick(tenant, "ns", "first", "uid-A", []model.Decision{m140Decision("p1", 0.20)},
		nil, 0, 0.01, "dryRun", true)
	if v, ok := gaugeValue(t, family(t, "phorvex_tenant_lambda"), map[string]string{"tenant": tenant}); !ok || v != 0.20 {
		t.Fatalf("unique owner: legacy series = %v present=%v, want 0.20", v, ok)
	}

	// Collision: a second owner appears with a different lambda.
	SetTenantOwnerCount(tenant, 2)
	PublishTick(tenant, "ns", "second", "uid-B", []model.Decision{m140Decision("p2", 0.90)},
		nil, 0, 0.01, "dryRun", false)

	if _, ok := gaugeValue(t, family(t, "phorvex_tenant_lambda"), map[string]string{"tenant": tenant}); ok {
		t.Fatal("legacy per-tenant lambda survived a collision; a stale sample is served indefinitely")
	}
	a, okA := gaugeValue(t, family(t, "phorvex_policy_lambda"), map[string]string{"tenant": tenant, "uid": "uid-A"})
	b, okB := gaugeValue(t, family(t, "phorvex_policy_lambda"), map[string]string{"tenant": tenant, "uid": "uid-B"})
	if !okA || !okB || a != 0.20 || b != 0.90 {
		t.Fatalf("per-owner series wrong: A=%v(%v) B=%v(%v), want 0.20 and 0.90", a, okA, b, okB)
	}
	if v, _ := gaugeValue(t, family(t, "phorvex_tenant_collisions"), map[string]string{"tenant": tenant}); v != 2 {
		t.Fatalf("collision gauge = %v, want 2", v)
	}

	// Uniqueness returns: the legacy series is republished from the SURVIVOR's own sample.
	ResetOwner(tenant, "ns", "second", "uid-B")
	SetTenantOwnerCount(tenant, 1)
	PublishTick(tenant, "ns", "first", "uid-A", []model.Decision{m140Decision("p1", 0.20)},
		nil, 0, 0.01, "dryRun", true)
	if v, ok := gaugeValue(t, family(t, "phorvex_tenant_lambda"), map[string]string{"tenant": tenant}); !ok || v != 0.20 {
		t.Fatalf("legacy series not restored from the survivor: %v present=%v", v, ok)
	}
	if _, ok := gaugeValue(t, family(t, "phorvex_policy_lambda"), map[string]string{"tenant": tenant, "uid": "uid-B"}); ok {
		t.Fatal("removed owner's per-policy series survived")
	}
}

// One owner's tick must not delete another owner's per-pod gauges. On baseline ResetTenant
// matched on the tenant label alone, so co-resident policies wiped each other every tick.
func TestM140_OwnerTickDoesNotDeleteSurvivorPodSeries(t *testing.T) {
	const tenant = "m140-podseries"
	PublishTick(tenant, "ns", "first", "uid-A", []model.Decision{m140Decision("pa", 0.2)},
		nil, 0, 0.01, "dryRun", false)
	PublishTick(tenant, "ns", "second", "uid-B", []model.Decision{m140Decision("pb", 0.9)},
		nil, 0, 0.01, "dryRun", false)

	if _, ok := gaugeValue(t, family(t, "phorvex_pod_risk_score"),
		map[string]string{"tenant": tenant, "pod": "pa", "uid": "uid-A"}); !ok {
		t.Fatal("the second owner's tick deleted the first owner's per-pod series")
	}

	// Removing one owner deletes only its own series.
	ResetOwner(tenant, "ns", "first", "uid-A")
	if _, ok := gaugeValue(t, family(t, "phorvex_pod_risk_score"),
		map[string]string{"tenant": tenant, "pod": "pb", "uid": "uid-B"}); !ok {
		t.Fatal("removing one owner deleted the survivor's per-pod series")
	}
	if _, ok := gaugeValue(t, family(t, "phorvex_pod_risk_score"),
		map[string]string{"tenant": tenant, "pod": "pa", "uid": "uid-A"}); ok {
		t.Fatal("removed owner's per-pod series survived")
	}
}

// With no decisions nothing is published, so a live "seed applied" check must use the first
// tick that actually produces decisions.
func TestM140_ZeroDecisionTickPublishesNoLambdaSample(t *testing.T) {
	const tenant = "m140-nodecisions"
	SetTenantOwnerCount(tenant, 1)
	PublishTick(tenant, "ns", "only", "uid-Z", nil, nil, 0, 0.01, "dryRun", true)
	if _, ok := gaugeValue(t, family(t, "phorvex_policy_lambda"), map[string]string{"tenant": tenant, "uid": "uid-Z"}); ok {
		t.Fatal("a tick with no decisions published a lambda sample it never observed")
	}
}
