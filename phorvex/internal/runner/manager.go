/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package runner is the per-tenant orchestration: it holds the live set of
// PhorvexPolicies (the tenant registry), and a single tick Runnable that, each base
// interval, builds ONE cluster ingest snapshot and processes every DUE tenant
// (ingest -> graph -> exposure -> decide -> audit/metrics -> [active] actuate). One
// snapshot shared across tenants keeps a tick cheap (NFR1). Per-tenant cadence is
// honored by skipping a tenant until its own tickInterval has elapsed.
package runner

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/recon"
)

type policyEntry struct {
	key       types.NamespacedName
	tenant    string
	namespace string
	spec      v1alpha1.PhorvexPolicySpec
	selector  labels.Selector
	lastTick  time.Time
}

// Manager owns the tenant registry and the tick loop.
type Manager struct {
	Client        client.Client
	Clock         *exposure.Clock
	Optimizer     decision.Optimizer
	Audit         *audit.Logger
	MetricsSource ingest.MetricsSource
	Actuator      actuator.Actuator
	KillSwitch    *KillSwitch
	BaseInterval  time.Duration
	// PerTickTimeout bounds one tick so a slow/hung API server cannot wedge the loop
	// goroutine indefinitely (P4b livelock fix). 0 => defaulted in Start.
	PerTickTimeout time.Duration
	Log            logr.Logger

	mu       sync.RWMutex
	policies map[string]*policyEntry
}

// NewManager constructs a Manager with sane defaults for any nil collaborators.
func NewManager(c client.Client, log logr.Logger) *Manager {
	src, _ := ingest.SourceRegistry.Default()
	// P-PHYSICS (UCW): make the discovered-physics recon-EMR profile the engine default
	// (byte-identical to standard-recon at nil-data; lifts only under measured dispersion).
	recon.Registry.SetDefault("ucw-recon")
	return &Manager{
		Client:        c,
		Clock:         exposure.NewClock(),
		Optimizer:     decision.NewCoverageEngine(), // P1 default brain
		Audit:         audit.New(log, nil),
		MetricsSource: src,
		Actuator:      selectActuator(c, log), // P-ACTUATOR: native vs Phoenix adapter
		KillSwitch:    &KillSwitch{Client: c},
		BaseInterval:  10 * time.Second,
		Log:           log.WithName("runner"),
		policies:      map[string]*policyEntry{},
	}
}

// selectActuator picks Phorvex's hands: the native actuator (its own client-go hands,
// PHORVEX_ACTUATOR=native) or the Phoenix adapter (default — drives UNMODIFIED Phoenix via
// SecurityEvent/AMTD CRs). Both satisfy the Actuator interface; the brain is unchanged.
func selectActuator(c client.Client, log logr.Logger) actuator.Actuator {
	if os.Getenv("PHORVEX_ACTUATOR") == "native" {
		log.WithName("runner").Info("actuator=native (Phorvex own hands; direct client-go enactment, no Phoenix CRDs)")
		return actuator.NewNativeActuator(c)
	}
	return actuator.NewPhoenixActuator(c)
}

// Upsert adds or updates a tenant policy in the registry.
func (m *Manager) Upsert(p *v1alpha1.PhorvexPolicy) error {
	sel, err := metav1LabelSelector(p)
	if err != nil {
		return err
	}
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := m.policies[key.String()]
	last := time.Time{}
	if existing != nil {
		last = existing.lastTick
	}
	m.policies[key.String()] = &policyEntry{
		key:       key,
		tenant:    p.EffectiveTenant(),
		namespace: p.Namespace,
		spec:      *p.Spec.DeepCopy(),
		selector:  sel,
		lastTick:  last,
	}
	return nil
}

// Remove drops a tenant policy and clears its metric series.
func (m *Manager) Remove(key types.NamespacedName) {
	m.mu.Lock()
	e := m.policies[key.String()]
	delete(m.policies, key.String())
	m.mu.Unlock()
	if e != nil {
		metrics.ResetTenant(e.tenant)
	}
}

// Start implements manager.Runnable: it runs the tick loop until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) error {
	if m.BaseInterval <= 0 {
		m.BaseInterval = 10 * time.Second
	}
	if m.PerTickTimeout <= 0 {
		// a tick must finish well within a few intervals; cap so a hung API can't wedge it.
		m.PerTickTimeout = 4 * m.BaseInterval
		if m.PerTickTimeout > 2*time.Minute {
			m.PerTickTimeout = 2 * time.Minute
		}
	}
	t := time.NewTicker(m.BaseInterval)
	defer t.Stop()
	m.Log.Info("phorvex tick loop started", "baseInterval", m.BaseInterval.String(), "perTickTimeout", m.PerTickTimeout.String())
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			// [P4b livelock fix] bound each tick: a slow/hung API server makes the tick ctx
			// expire, CollectSnapshot/Get return promptly, the tick SKIPS (and a timed-out
			// kill-switch read fail-CLOSES per FIX 1) — the loop never wedges.
			tctx, cancel := context.WithTimeout(ctx, m.PerTickTimeout)
			m.tick(tctx)
			cancel()
		}
	}
}

// reconcileWedged converges crash-wedged actuator state (a double-leader warm-swap; an
// orphaned quarantine NetworkPolicy) for each managed namespace, idempotently. Runs every
// tick INDEPENDENT of tenant cadence (a wedged double-leader must converge even if no policy
// is "due" this tick).
func (m *Manager) reconcileWedged(ctx context.Context, namespaces []string) {
	for _, ns := range namespaces {
		if n, err := actuator.ResumeWarmSwaps(ctx, m.Client, ns); err == nil && n > 0 {
			m.Log.Info("warm-swap resume: converged wedged swap", "namespace", ns, "reaped", n)
		}
		if n, err := actuator.GCOrphanedQuarantineNPs(ctx, m.Client, ns); err == nil && n > 0 {
			m.Log.Info("orphan-GC: reaped quarantine NetworkPolicy", "namespace", ns, "reaped", n)
		}
	}
}

// tick builds one cluster snapshot and processes all due tenants.
func (m *Manager) tick(ctx context.Context) {
	m.mu.RLock()
	due := make([]*policyEntry, 0, len(m.policies))
	nsSet := map[string]bool{}
	now := time.Now()
	for _, e := range m.policies {
		if e.namespace != "" {
			nsSet[e.namespace] = true
		}
		if now.Sub(e.lastTick) >= e.spec.EffectiveTickInterval() {
			due = append(due, e)
		}
	}
	m.mu.RUnlock()

	killEngaged := m.KillSwitch.Engaged(ctx)
	metrics.SetKillSwitch(killEngaged)

	// [P4b] converge crash-WEDGED actuator state (double-leader warm-swap; orphaned quarantine
	// NetworkPolicy) EVERY tick, independent of tenant cadence — unless the kill-switch is
	// engaged (a deliberate global freeze) or actuation is unavailable.
	if !killEngaged && m.Actuator != nil && len(nsSet) > 0 {
		nss := make([]string, 0, len(nsSet))
		for ns := range nsSet {
			nss = append(nss, ns)
		}
		m.reconcileWedged(ctx, nss)
	}

	if len(due) == 0 {
		return
	}

	snap, err := ingest.CollectSnapshot(ctx, m.Client, now, genericAssetValue)
	if err != nil {
		m.Log.Error(err, "ingest snapshot failed; skipping tick")
		return
	}

	for _, e := range due {
		m.processTenant(ctx, snap, e, killEngaged)
	}
}

// genericAssetValue is the tenant-INDEPENDENT pod value used to weight the shared
// blast-radius graph (per-tenant label weights are applied later in the context
// provider). It values mounted secrets and stateful pods, with a small baseline.
func genericAssetValue(p *model.Pod) float64 {
	v := 0.1 + 0.8*float64(len(p.MountedSecrets))
	if p.Stateful {
		v += 0.3
	}
	return v
}

// buildInfectedSet (P-CONTEXT live-beta Tier-1) reconstructs the per-tick infected set:
// pods with a high/critical TargetsPod event (an exploit+ foothold). It is a lossy
// LOWER bound (under-counts — the safe direction, never inflates cover). Empty => no
// frontier lift => byte-identical to the pre-P-CONTEXT decision.
func buildInfectedSet(snap *ingest.Snapshot) map[string]bool {
	inf := map[string]bool{}
	for key, evs := range snap.EventByPod {
		for i := range evs {
			if isHighSeverity(evs[i].ThreatLevel) {
				inf[key] = true
				break
			}
		}
	}
	return inf
}

func isHighSeverity(tl string) bool {
	switch tl {
	case "high", "High", "HIGH", "critical", "Critical", "CRITICAL":
		return true
	}
	return false
}

// infectionFrontier returns 1 + kappa (kappa=0.5) when any graph-neighbor is in the
// infected set, else 1.0 (honest-absent).
func infectionFrontier(nbKeys []string, infected map[string]bool) float64 {
	for _, nb := range nbKeys {
		if infected[nb] {
			return 1.5
		}
	}
	return 1.0
}

func (m *Manager) processTenant(ctx context.Context, snap *ingest.Snapshot, e *policyEntry, killEngaged bool) {
	start := time.Now()
	pol := buildPolicy(e)

	// P-PHYSICS (UCW): derive the discovered per-pod physics from the live scan, so the
	// recon-EMR + GPU-conservation laws read measured supply/demand + dispersion instead
	// of hand-specced constants. Honest-absent (NeutralPhysics) when no scan answers.
	_, physicsByKey := platform.Derive(snap)
	infected := buildInfectedSet(snap) // P-CONTEXT live-beta Tier-1 frontier

	// Select this tenant's pods.
	var selPods []*model.Pod
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.Namespace != e.namespace {
			continue
		}
		if e.selector != nil && !e.selector.Matches(labels.Set(p.Labels)) {
			continue
		}
		selPods = append(selPods, p)
	}

	names := make([]string, 0, len(selPods))
	for _, p := range selPods {
		names = append(names, p.Name)
	}
	tele := map[string]model.Telemetry{}
	if m.MetricsSource != nil {
		if t, err := m.MetricsSource.PodMetrics(ctx, e.namespace, names); err == nil {
			tele = t
		}
	}

	keep := make(map[string]struct{}, len(selPods))
	views := make([]*model.WorkloadView, 0, len(selPods))
	for _, p := range selPods {
		t := tele[p.Name]
		m.Clock.Observe(exposure.Observation{
			Tenant:    pol.Tenant,
			Namespace: p.Namespace,
			Pod:       p.Name,
			StartedAt: p.StartedAt,
			Fingerprints: map[string]string{
				model.VarPodIdentity:   p.UID,
				model.VarNodePlacement: p.Node,
			},
		}, snap.Now)
		keep[exposure.SlotKey(pol.Tenant, p.Namespace, p.Name)] = struct{}{}
		exp := m.Clock.Since(pol.Tenant, p.Namespace, p.Name, snap.Now)

		events := append([]model.SecurityEventInfo{}, snap.EventByPod[p.Namespace+"/"+p.Name]...)
		nbKeys := snap.Graph.Neighbors(p.Namespace, p.Name)
		neighbors := make([]model.NeighborRef, 0, len(nbKeys))
		for _, nb := range nbKeys {
			for _, ne := range snap.EventByPod[nb] {
				ne.TargetsPod = false
				events = append(events, ne)
			}
			val := 0.0
			if np, ok := snap.PodByKey[nb]; ok {
				val = genericAssetValue(np)
			}
			neighbors = append(neighbors, model.NeighborRef{Key: nb, Value: val})
		}

		ph, okPh := physicsByKey[p.Namespace+"/"+p.Name]
		if !okPh {
			ph = model.NeutralPhysics()
		}
		views = append(views, &model.WorkloadView{
			Pod:                *p,
			Telemetry:          t,
			Phase:              ingest.PhaseOf(*p, t),
			BlastRadius:        snap.Graph.BlastRadius(p.Namespace, p.Name),
			NeighborCount:      snap.Graph.NeighborCount(p.Namespace, p.Name),
			Neighbors:          neighbors,
			Events:             events,
			ExposureByVariable: exp,
			Physics:            ph,
			InfectionFrontier:  infectionFrontier(nbKeys, infected),
		})
	}

	decisions := m.Optimizer.Decide(views, pol)

	// Effective actuation gate (FR8): a tenant is dry-run if its policy says so OR its
	// namespace is annotated phorvex.ai/dry-run; the global kill-switch suppresses on top.
	nsDryRun := snap.DryRunNamespaces[e.namespace]
	effectiveDryRun := pol.DryRun || nsDryRun
	if effectiveDryRun {
		for i := range decisions {
			decisions[i].DryRun = true // honest audit: reflect the mode actually applied
		}
	}

	// Actuate FIRST (active mode) so the audit + metrics reflect what ACTUALLY fired
	// (actuate marks decisions[i].Actuated on a successful emit).
	actuated := 0
	if !effectiveDryRun && !killEngaged && m.Actuator != nil {
		viewByKey := make(map[string]*model.WorkloadView, len(views))
		for _, v := range views {
			viewByKey[v.Pod.Namespace+"/"+v.Pod.Name] = v
		}
		actuated = m.actuate(ctx, e, pol, decisions, viewByKey)
	}

	selected, infeasible := 0, 0
	for i := range decisions {
		m.Audit.Record(decisions[i])
		if decisions[i].Selected {
			selected++
		}
		if decisions[i].Action == model.ActionNoop && !decisions[i].Feasible {
			infeasible++
		}
	}

	exposuresForMetrics := make(map[string]map[string]float64, len(views))
	for _, v := range views {
		em := make(map[string]float64, len(v.ExposureByVariable))
		for k, d := range v.ExposureByVariable {
			em[k] = d.Seconds()
		}
		exposuresForMetrics[v.Pod.Namespace+"/"+v.Pod.Name] = em
	}

	dur := time.Since(start)
	metrics.PublishTick(pol.Tenant, decisions, exposuresForMetrics, selected, dur.Seconds(), pol.Mode)
	m.Audit.TickSummary(pol.Tenant, len(decisions), selected, infeasible, dur, pol.Mode, killEngaged)
	m.Clock.RetainTenant(pol.Tenant, keep)
	m.updateStatus(ctx, e, len(views), selected, actuated, killEngaged, snap.Now)

	m.mu.Lock()
	if cur := m.policies[e.key.String()]; cur != nil {
		cur.lastTick = snap.Now
	}
	m.mu.Unlock()
}

func (m *Manager) actuate(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, viewByKey map[string]*model.WorkloadView) int {
	target := actuator.TenantTarget{
		Tenant:         pol.Tenant,
		Namespace:      e.namespace,
		MatchLabels:    e.spec.Selector.MatchLabels,
		EnabledActions: pol.EnabledActions,
	}
	if err := m.Actuator.EnsurePolicy(ctx, target); err != nil {
		m.Log.Error(err, "actuator EnsurePolicy failed; suppressing actuation this tick", "tenant", pol.Tenant)
		return 0
	}
	actuated := 0
	for i := range decisions {
		if !decisions[i].Selected {
			continue
		}
		// Inviolability guard at the emit boundary (defense in depth): a selected move is
		// ALWAYS feasible (the action-set generator excluded infeasible moves before
		// selection), but never emit one that is not — and shout if the invariant breaks.
		if !decisions[i].Feasible || decisions[i].Action == model.ActionNoop {
			m.Log.Error(nil, "INVARIANT VIOLATION: a selected move was infeasible/noop; refusing to emit",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			continue
		}
		// P-ACTUATOR emit-boundary feasibility RE-GATE: re-run the SAME move-keyed gate the
		// generator used, on live view state, immediately before enacting — never trust ONLY
		// the cached Feasible bool. Action-agnostic (keys on Move{Action}), so it covers all
		// native action types uniformly. A veto refuses the emit and shouts.
		//
		// [P4c D3/F5 FAIL-CLOSED FIX] A MISSING live view for the target is UNCERTAINTY, not a
		// pass: previously the re-gate ran only inside `; ok {`, so a map-miss SKIPPED the gate
		// (fail-OPEN) and actuated on the stale cached bool. Now a map-miss VETOES (fail-CLOSED):
		// we never actuate a move whose target we cannot re-verify against live state.
		v, ok := viewByKey[decisions[i].Namespace+"/"+decisions[i].Pod]
		if !ok {
			m.Log.Error(nil, "EMIT-BOUNDARY VETO (fail-closed): no live view for the target; refusing to actuate",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			continue
		}
		if verdict := feasibility.Evaluate(v, model.Move{Action: decisions[i].Action}, pol); !verdict.Feasible {
			m.Log.Error(nil, "EMIT-BOUNDARY VETO: refusing infeasible move at actuate boundary",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action, "reason", verdict.Reason)
			continue
		}
		score := decisions[i].Risk
		if score > 1 {
			score = 1
		}
		res, err := m.Actuator.Actuate(ctx, actuator.Request{
			Tenant:    pol.Tenant,
			Namespace: decisions[i].Namespace,
			Pod:       decisions[i].Pod,
			Action:    decisions[i].Action,
			Reason:    decisions[i].Reason,
			Score:     score,
		})
		if err != nil {
			m.Log.Error(err, "actuate failed", "pod", decisions[i].Namespace+"/"+decisions[i].Pod)
			continue
		}
		if res.Emitted {
			decisions[i].Actuated = true
			// Carry the native actuator's forensic fields into the audit (empty for Phoenix).
			decisions[i].Handler = res.Handler
			decisions[i].ObjectsTouched = res.ObjectsTouched
			decisions[i].RollbackRef = res.RollbackRef
			decisions[i].MutationKind = res.MutationKind
			actuated++
			metrics.RecordActuation(pol.Tenant, string(decisions[i].Action))
		}
	}
	return actuated
}

func buildPolicy(e *policyEntry) model.Policy {
	s := &e.spec
	enabled := map[model.Action]bool{}
	for _, a := range s.Actions.Enabled {
		enabled[model.Action(a)] = true
	}
	if len(enabled) == 0 {
		enabled[model.ActionRotate] = true
		enabled[model.ActionQuarantine] = true
	}
	return model.Policy{
		Tenant:                 e.tenant,
		Namespace:              e.namespace,
		Mode:                   s.EffectiveMode(),
		DryRun:                 s.IsDryRun(),
		Lambda:                 s.EffectiveLambda(),
		NormSparsity:           s.EffectiveNormSparsity(),
		FlowDisruption:         s.EffectiveFlowDisruption(),
		WeightSecrets:          s.EffectiveWeightSecrets(),
		BlastRadiusFromGraph:   s.AssetValue.BlastRadiusFromGraph,
		MaxMovesPerTick:        s.EffectiveMaxMovesPerTick(),
		TickInterval:           s.EffectiveTickInterval(),
		AntiOverRotationWindow: s.EffectiveAntiOverRotationWindow(),
		ProactiveFloor:         s.EffectiveProactiveFloor(),
		MinAvailableReplicas:   s.EffectiveMinAvailableReplicas(),
		P99Ms:                  s.SLO.P99Ms,
		MinTokensPerSec:        s.SLO.MinTokensPerSec,
		EventDriven:            s.Triggers.EventDriven,
		ReactiveOnly:           s.Triggers.ReactiveOnly,
		EnabledActions:         enabled,
		AssetWeightFromLabels:  s.AssetWeightFromLabels,
	}
}

// metav1LabelSelector compiles the policy's selector.
func metav1LabelSelector(p *v1alpha1.PhorvexPolicy) (labels.Selector, error) {
	return metav1SelAsSel(&p.Spec.Selector)
}
