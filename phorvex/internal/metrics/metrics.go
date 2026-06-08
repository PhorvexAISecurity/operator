/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package metrics publishes Phorvex's Prometheus signals (PRD FR6) onto the
// controller-runtime metrics registry, so they are scraped on the manager's existing
// /metrics endpoint. The per-pod risk gauge is the source series for the Grafana
// RISK HEATMAP (pods × risk). Per-pod series are re-published each tick and the
// departed tenant series are deleted, so the heatmap reflects the live fleet without
// unbounded series growth.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/internal/model"
)

var (
	podRisk = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_risk_score",
		Help: "Per-pod risk score this tick (Grafana heatmap source).",
	}, []string{"tenant", "namespace", "pod"})

	podCost = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_switching_cost",
		Help: "Per-pod switching (disruption) cost of the best candidate move this tick.",
	}, []string{"tenant", "namespace", "pod"})

	podNet = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_net_benefit",
		Help: "Per-pod net benefit (risk - lambda*cost) of the best candidate move this tick.",
	}, []string{"tenant", "namespace", "pod"})

	podBlast = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_blast_radius",
		Help: "Per-pod normalized blast-radius (reachability) score.",
	}, []string{"tenant", "namespace", "pod"})

	podExposure = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_exposure_seconds",
		Help: "Per-pod, per-variable exposure clock (seconds since the variable last changed).",
	}, []string{"tenant", "namespace", "pod", "variable"})

	podPerDollar = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_per_dollar",
		Help: "Per-pod recon-facts-invalidated-per-dollar of the best move (P1 coverage engine).",
	}, []string{"tenant", "namespace", "pod"})

	podProactiveRate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_proactive_rate",
		Help: "Per-pod emergent proactive firing rate (perDollar - lambda); >0 means due to fire now.",
	}, []string{"tenant", "namespace", "pod"})

	tenantLambda = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_tenant_lambda",
		Help: "Solved dual-descent budget shadow-price lambda per tenant.",
	}, []string{"tenant"})

	selectedPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_selected_moves",
		Help: "Number of moves SELECTED (within budget) this tick per tenant.",
	}, []string{"tenant"})

	protectedPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_protected_pods",
		Help: "Number of pods this tenant policy currently protects.",
	}, []string{"tenant"})

	killSwitch = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_kill_switch_engaged",
		Help: "1 when the global kill-switch is engaged (all actuation suppressed).",
	})

	decisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_decisions_total",
		Help: "Decisions emitted, by tenant/action/mode/selected.",
	}, []string{"tenant", "action", "mode", "selected"})

	actuationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_actuations_total",
		Help: "SecurityEvents actually emitted to Phoenix (active mode only).",
	}, []string{"tenant", "action"})

	ticksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_ticks_total",
		Help: "Decision ticks executed, by tenant.",
	}, []string{"tenant"})

	tickDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "phorvex_tick_duration_seconds",
		Help:    "Wall-clock duration of a decision tick (NFR1: <1s for <=1000 pods).",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"tenant"})
)

func init() {
	crmetrics.Registry.MustRegister(
		podRisk, podCost, podNet, podBlast, podExposure,
		podPerDollar, podProactiveRate, tenantLambda,
		selectedPods, protectedPods, killSwitch,
		decisionsTotal, actuationsTotal, ticksTotal, tickDuration,
	)
}

// SetKillSwitch reflects the global kill-switch state.
func SetKillSwitch(engaged bool) {
	if engaged {
		killSwitch.Set(1)
		return
	}
	killSwitch.Set(0)
}

// ResetTenant clears a tenant's per-pod series (call before re-publishing a tick, and
// on tenant removal) so departed pods do not linger in the heatmap.
func ResetTenant(tenant string) {
	m := prometheus.Labels{"tenant": tenant}
	podRisk.DeletePartialMatch(m)
	podCost.DeletePartialMatch(m)
	podNet.DeletePartialMatch(m)
	podBlast.DeletePartialMatch(m)
	podExposure.DeletePartialMatch(m)
	podPerDollar.DeletePartialMatch(m)
	podProactiveRate.DeletePartialMatch(m)
}

// PublishTick records one tenant's tick: re-publishes per-pod gauges, the rollups,
// and the counters.
func PublishTick(tenant string, decisions []model.Decision, exposures map[string]map[string]float64, selected int, durSeconds float64, mode string) {
	ResetTenant(tenant)
	ticksTotal.WithLabelValues(tenant).Inc()
	tickDuration.WithLabelValues(tenant).Observe(durSeconds)
	protectedPods.WithLabelValues(tenant).Set(float64(len(decisions)))
	selectedPods.WithLabelValues(tenant).Set(float64(selected))

	for _, d := range decisions {
		podRisk.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.Risk)
		podCost.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.Cost)
		podNet.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.Net)
		podBlast.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.BlastRadius)
		podPerDollar.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.PerDollar)
		podProactiveRate.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.ProactiveRate)
		decisionsTotal.WithLabelValues(tenant, string(d.Action), mode, boolStr(d.Selected)).Inc()
	}
	if len(decisions) > 0 {
		tenantLambda.WithLabelValues(tenant).Set(decisions[0].Lambda)
	}
	// Per-variable exposure: exposures[ns/pod][variable] = seconds.
	for nsPod, vars := range exposures {
		ns, pod := splitNSPod(nsPod)
		for variable, secs := range vars {
			podExposure.WithLabelValues(tenant, ns, pod, variable).Set(secs)
		}
	}
}

// RecordActuation counts a real emit to Phoenix (active mode).
func RecordActuation(tenant, action string) {
	actuationsTotal.WithLabelValues(tenant, action).Inc()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func splitNSPod(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:]
		}
	}
	return "", s
}
