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
		Help: "Legacy per-pod full-value/ECost reporting ratio; ECost is dimensionless, not dollars.",
	}, []string{"tenant", "namespace", "pod"})

	podProactiveRate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_pod_proactive_rate",
		Help: "Legacy reporting value perDollar-lambda; it is not the P1 action selector.",
	}, []string{"tenant", "namespace", "pod"})

	tenantLambda = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_tenant_lambda",
		Help: "Legacy mixed runtime lambda per tenant; move-pressure-updated ECost coefficient, not a certified exact dual.",
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

	killSwitchStatusDisagreement = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_kill_switch_status_disagreement",
		Help: "1 when the runtime kill-switch state is unknown to or disagrees with a PhorvexPolicy status.",
	}, []string{"namespace", "policy"})

	decisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_decisions_total",
		Help: "Decisions emitted, by tenant/action/mode/selected.",
	}, []string{"tenant", "action", "mode", "selected"})

	epssLookupTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_epss_lookup_total",
		Help: "EPSS cache lookups by outcome: hit (exact digest), repo-fallback (latest scan of the same repository), miss (M-141). A stale cache is a metric, not a surprise.",
	}, []string{"result"})

	eventsAgedOut = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_events_aged_out_total",
		Help: "Kill-chain evidence observations whose SecurityEvent aging weight reached 0 (age >= tau_ev or no timestamp), by tenant (M-27).",
	}, []string{"tenant"})

	actuationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_actuations_total",
		Help: "SecurityEvents actually emitted to Phoenix (active mode only).",
	}, []string{"tenant", "action"})

	ticksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_ticks_total",
		Help: "Decision ticks executed, by tenant and policy. The policy label keeps two policies that share one tenant name from collapsing into a single series (M-145).",
	}, []string{"tenant", "policy"})

	actionSetRejections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_action_set_rejections_total",
		Help: "Decision ticks rejected before optimization because the generated action set violated a structural invariant.",
	}, []string{"tenant", "reason"})

	scrapeFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_scrape_failures_total",
		Help: "Telemetry scrape failures by source (a failed scrape is degradation, not a measured zero).",
	}, []string{"source"})
	sloGateSkippedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_slo_gate_skipped_total",
		Help: "SLO gate skipped because latency headroom was not a usable measurement (skip+count, never block).",
	}, []string{"tenant", "reason"})
	costNaNUnactionable = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_cost_nan_unactionable_total",
		Help: "Actions excluded fail-conservative because an action-relevant cost feature was NaN.",
	}, []string{"tenant", "namespace", "pod", "action", "feature"})

	candidatesExcludedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_candidates_excluded_total",
		Help: "Candidate (asset,action) pairs excluded by the T1-E capability gate BEFORE scoring, by reason (not-installable|no-cover|capability-unsupported|no-rbac).",
	}, []string{"tenant", "action", "reason"})
	candidatesRBACUnknownTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_candidates_rbac_unknown_total",
		Help: "Candidates whose SSAR errored so RBAC could not be confirmed — NOT excluded (fail-open, P-NO-FREEZE); flags a degraded apiserver, not a policy problem.",
	}, []string{"tenant", "action"})

	requestDrainAborted = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "phorvex_request_drain_aborted_requests",
		Help:    "In-flight requests aborted by each successful request-drain actuation.",
		Buckets: []float64{0, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000},
	}, []string{"tenant", "namespace", "pod"})

	tickDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "phorvex_tick_duration_seconds",
		Help:    "Wall-clock duration of a decision tick (NFR1: <1s for <=1000 pods).",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"tenant"})

	// ---- RLS cost-calibrator observability (PHVX-10c / PHORVEXSEC-98) ----
	//
	// Primed() alone answers WHETHER the calibrator has learned anything. It does not answer WHY
	// not, and "why not" is the whole question: the calibrator only updates when the loop pairs an
	// emitted rotation with a newly-Ready replacement pod, and that pairing can fail for reasons
	// with completely different fixes. The outcome label separates them:
	//
	//	matched   - a replacement was found; theta was updated from a real measurement.
	//	censored  - no replacement became Ready inside the observation window; the rotation trains
	//	            at the censored maximum instead of a measured value.
	//	abandoned - the ORIGINAL pod UID was still alive when the window expired, so the actuation
	//	            never took effect and nothing is learned. High counts here mean the emit path is
	//	            failing, not the cost model.
	//
	// A high attempt count with near-zero `matched` is the failure mode PHVX-2 alleged, reached by a
	// different mechanism, and it is invisible from Primed() alone.
	rlsObservations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_rls_rotation_observations_total",
		Help: "Rotation cost observations resolved, by outcome (matched|censored|abandoned).",
	}, []string{"tenant", "outcome"})
	rlsPending = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_rls_rotations_pending",
		Help: "Rotations awaiting a cost observation right now.",
	}, []string{"tenant"})
	rlsPrimed = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_rls_primed",
		Help: "1 when the tenant's RLS has folded in at least one real observation; 0 = still the shipped prior.",
	}, []string{"tenant"})
	rlsUpdates = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_rls_updates_total",
		Help: "Observations folded into the tenant's RLS since process start (in-process state; resets on restart).",
	}, []string{"tenant"})
)

func init() {
	crmetrics.Registry.MustRegister(
		podRisk, podCost, podNet, podBlast, podExposure,
		podPerDollar, podProactiveRate, tenantLambda,
		selectedPods, protectedPods, killSwitch, killSwitchStatusDisagreement,
		decisionsTotal, actuationsTotal, ticksTotal, actionSetRejections, epssLookupTotal, eventsAgedOut,
		costNaNUnactionable, requestDrainAborted, tickDuration,
		rlsObservations, rlsPending, rlsPrimed, rlsUpdates,
		scrapeFailuresTotal, sloGateSkippedTotal,
		candidatesExcludedTotal, candidatesRBACUnknownTotal,
	)
}

// RecordCandidateExcluded counts a candidate excluded by the T1-E capability gate.
func RecordCandidateExcluded(tenant, action, reason string) {
	candidatesExcludedTotal.WithLabelValues(tenant, action, reason).Inc()
}

// RecordCandidateRBACUnknown counts a candidate whose SSAR errored (fail-open, not excluded).
func RecordCandidateRBACUnknown(tenant, action string) {
	candidatesRBACUnknownTotal.WithLabelValues(tenant, action).Inc()
}

// RecordScrapeFailure counts a telemetry-source scrape failure by source (M-113/M-130): a failed
// scrape is a measured degradation, not a silent measured zero.
func RecordScrapeFailure(source string) {
	scrapeFailuresTotal.WithLabelValues(source).Inc()
}

// RecordSLOGateSkipped counts an SLO gate skipped because latency headroom was not a usable
// measurement (T1-C P-NO-FREEZE): absence skips-and-counts, never blocks. reason = absent|stale|error.
func RecordSLOGateSkipped(tenant, reason string) {
	sloGateSkippedTotal.WithLabelValues(tenant, reason).Inc()
}

// SetKillSwitch reflects the global kill-switch state.
func SetKillSwitch(engaged bool) {
	if engaged {
		killSwitch.Set(1)
		return
	}
	killSwitch.Set(0)
}

// SetKillSwitchStatusDisagreement exposes a stale/unknown policy readout separately from the
// runtime gauge. A successful status write clears it; a failed read or a failed transition leaves
// it at 1 so Prometheus can alert instead of trusting a silently stale safety-control field.
func SetKillSwitchStatusDisagreement(namespace, policy string, disagrees bool) {
	v := 0.0
	if disagrees {
		v = 1
	}
	killSwitchStatusDisagreement.WithLabelValues(namespace, policy).Set(v)
}

// ResetKillSwitchStatus removes the bounded per-policy series when a policy leaves the registry.
func ResetKillSwitchStatus(namespace, policy string) {
	killSwitchStatusDisagreement.DeleteLabelValues(namespace, policy)
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
func PublishTick(tenant, policy string, decisions []model.Decision, exposures map[string]map[string]float64, selected int, durSeconds float64, mode string) {
	ResetTenant(tenant)
	ticksTotal.WithLabelValues(tenant, policy).Inc()
	tickDuration.WithLabelValues(tenant).Observe(durSeconds)
	protectedPods.WithLabelValues(tenant).Set(float64(len(decisions)))
	selectedPods.WithLabelValues(tenant).Set(float64(selected))

	for _, d := range decisions {
		// Keep the legacy Prometheus metric stable while the versioned Decision/audit
		// contract separates P1 coverage value from deprecated P0 threat risk.
		podRisk.WithLabelValues(tenant, d.Namespace, d.Pod).Set(d.DecisionValue())
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
// RecordEPSSLookup counts one exploitability-cache lookup by outcome (M-141).
func RecordEPSSLookup(result string) {
	epssLookupTotal.WithLabelValues(result).Inc()
}

// EPSSLookupCounter exposes one outcome's counter (tests and the scan report).
func EPSSLookupCounter(result string) prometheus.Counter {
	return epssLookupTotal.WithLabelValues(result)
}

// RecordEventAgedOut counts one assessment in which an ingested SecurityEvent carried
// weight 0 — it aged past tau_ev or had no timestamp (M-27).
func RecordEventAgedOut(tenant string) {
	eventsAgedOut.WithLabelValues(tenant).Inc()
}

func RecordActuation(tenant, action string) {
	actuationsTotal.WithLabelValues(tenant, action).Inc()
}

// RecordActionSetRejection counts a fail-closed tick before any decision or actuation.
func RecordActionSetRejection(tenant, reason string) {
	actionSetRejections.WithLabelValues(tenant, reason).Inc()
}

// RecordCostNaNUnactionable makes every fail-conservative NaN exclusion visible
// with enough bounded context to identify the broken signal and affected action.
func RecordCostNaNUnactionable(tenant, namespace, pod, action, feature string) {
	costNaNUnactionable.WithLabelValues(tenant, namespace, pod, action, feature).Inc()
}

// RecordRequestDrainAborted preserves the per-actuation abort count as a
// histogram rather than burying it in a note string. The sum/count series are the
// direct measurement seam for the future cutover-flow model.
func RecordRequestDrainAborted(tenant, namespace, pod string, aborted int) {
	if aborted < 0 {
		aborted = 0
	}
	requestDrainAborted.WithLabelValues(tenant, namespace, pod).Observe(float64(aborted))
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

// Outcome labels for ObserveRotationOutcome. Kept as constants so a typo cannot silently create a
// fourth series that nobody is looking at.
const (
	RLSMatched   = "matched"
	RLSCensored  = "censored"
	RLSAbandoned = "abandoned"
)

// ObserveRotationOutcome records how one pending rotation resolved. Call exactly once per rotation
// that leaves the pending set — not once per tick it is examined, or the ratio becomes a function of
// tick cadence rather than of matching success.
func ObserveRotationOutcome(tenant, outcome string) {
	rlsObservations.WithLabelValues(tenant, outcome).Inc()
}

// SetRotationsPending publishes the current backlog for a tenant.
func SetRotationsPending(tenant string, n int) {
	rlsPending.WithLabelValues(tenant).Set(float64(n))
}

// SetRLSState publishes whether a tenant's calibrator has left the prior, and how many observations
// it has folded in. Both are in-process values and reset when the operator restarts — which is
// itself worth seeing, because a calibrator that never survives long enough to prime is
// indistinguishable from one that never matches.
func SetRLSState(tenant string, primed bool, updates int) {
	v := 0.0
	if primed {
		v = 1
	}
	rlsPrimed.WithLabelValues(tenant).Set(v)
	rlsUpdates.WithLabelValues(tenant).Set(float64(updates))
}
