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
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/calib"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/slo"
)

type policyEntry struct {
	key       types.NamespacedName
	uid       string
	tenant    string
	namespace string
	spec      v1alpha1.PhorvexPolicySpec
	selector  labels.Selector
	lastTick  time.Time

	generation                  int64
	actionsUnsupportedTicks     int
	actionsUnsupportedSignature string
}

// pendingRotation holds the pre-action features until Kubernetes proves that a
// controller-created replacement UID reached Ready. knownUIDs prevents an already
// Ready sibling from being mistaken for the replacement.
type pendingRotation struct {
	tenant               string
	startedAt            time.Time
	referenceAtStart     time.Duration
	censorDeadline       time.Time
	view                 model.WorkloadView
	knownUIDs            map[string]struct{}
	minAvailableReplicas int
	selectionBound       slo.Bound
	costObserved         bool
}

// Manager owns the tenant registry and the tick loop.
type Manager struct {
	OwnershipReader client.Reader // uncached, read-only owner evidence
	// BoundaryReader bypasses informer staleness when checking M99 admission enforcement.
	BoundaryReader client.Reader
	Client         client.Client
	Clock          *exposure.Clock
	Intents        *exposure.Intents // M-23: per-action emit intent (cross-tick burst guard)
	Optimizer      decision.Optimizer
	Audit          *audit.Logger
	MetricsSource  ingest.MetricsSource
	// PromURL feeds the GPU-half physics witness (DCGM via Prometheus) on the live tick; empty =
	// K8s-only signals (GPU half stays honest-absent/neutral).
	PromURL  string
	Actuator actuator.Actuator
	// Authz is the T1-E SSAR capability checker (cached). nil disables the RBAC leg of the
	// gate (installability + cover + runtime-capability still apply); the boot layer wires
	// it from the cluster clientset so no-rbac exclusions become live.
	Authz *authz.Checker
	// PCIeClasses is the chart's hardware-class table for the PCIe denominator (M-114).
	PCIeClasses  ingest.PCIeClassTable
	KillSwitch   *KillSwitch
	BaseInterval time.Duration
	// PerTickTimeout bounds one tick so a slow/hung API server cannot wedge the loop
	// goroutine indefinitely (P4b livelock fix). 0 => defaulted in Start.
	PerTickTimeout time.Duration
	Log            logr.Logger
	// Calibration runs the PHVX-74 scale fit in shadow. Its values are exported and
	// monitored but never read by production scoring.
	Calibration *calib.Runtime

	Recorder record.EventRecorder
	// ActionsSupportedDebounce is the number of consecutive mismatching policy ticks
	// required before status becomes False. <=0 uses the default.
	ActionsSupportedDebounce int

	// Disruption is the Phorvex action/impact ledger. It records completed
	// structural-zero actions, explicit unknown-impact outcomes, and measured or
	// censored rotation disruption. Nil disables recording; it observes and never gates.
	Disruption *slo.Ledger

	// Decision trace is observational. Build identity is resolved once at
	// startup; disabling the trace is used only for non-interference tests.
	DecisionTraceEnabled bool
	BrainImage           string
	GitSHA               string

	mu sync.RWMutex
	// emits is the per-policy ledger of ENACTED-move timestamps that feeds the rolling
	// Status.Actuated / Status.MovesThisWindow (PHORVEXSEC-176). It lives on the Manager,
	// not the policyEntry, so a spec edit (Upsert) does not forget real actuations. It is
	// in-memory only: a restart or leadership change can only UNDER-report until the next
	// emit — never claim an actuation the running brain did not perform.
	emits map[string][]time.Time
	// degraded tracks each telemetry source's outage state so a whole-source failure is
	// logged ONCE on transition (down / recovered), surfaced as a policy condition and
	// counted — never one ERROR line per tick (PHORVEXSEC-200 / M-113, P-LOUD-OUTAGE).
	degraded map[string]*sourceOutage
	policies map[string]*policyEntry
	// untrustedEvents is the last tick's count of SecurityEvents that supplied no belief
	// evidence because their creator was not an allowlisted detector (M-94). It exists so the
	// stream is reported ONCE per transition instead of every tick.
	untrustedEvents int
	// Accessed only by the single tick loop. The RLS outcome is capped after its
	// [0,2] observation window, but ledger-enabled censored entries remain here so
	// their disruption floor keeps increasing until recovery is actually observed.
	pendingRotations map[string]pendingRotation
}

// NewManager constructs a Manager with sane defaults for any nil collaborators.
func NewManager(c client.Client, log logr.Logger) *Manager {
	src, _ := ingest.SourceRegistry.Default()
	// P-PHYSICS (UCW): make the discovered-physics recon-EMR profile the engine default
	// (byte-identical to standard-recon at nil-data; lifts only under measured dispersion).
	recon.Registry.SetDefault("ucw-recon")
	identity := buildinfo.Current()
	return &Manager{
		Client:          c,
		OwnershipReader: c,
		Clock:           exposure.NewClock(),
		Intents:         exposure.NewIntents(),
		Optimizer:       decision.NewCoverageEngine(), // P1 default brain
		Audit:           audit.New(log, nil),
		MetricsSource:   src,
		Actuator:        selectActuator(c, log), // P-ACTUATOR: native vs Phoenix adapter
		KillSwitch:      &KillSwitch{Client: c},
		BaseInterval:    10 * time.Second,
		Log:             log.WithName("runner"),
		Calibration:     calib.NewRuntime(calib.RuntimeConfig{}, log),
		// Retains a month, the longest SLO window anyone has proposed, so an entry
		// can never be evicted while a ratio could still be computed from it. The
		// ledger observes only: nothing reads it to gate a move yet.
		Disruption:           slo.NewLedger(30 * 24 * time.Hour),
		DecisionTraceEnabled: true,
		BrainImage:           identity.BrainImage,
		GitSHA:               identity.GitSHA,
		policies:             map[string]*policyEntry{},

		ActionsSupportedDebounce: DefaultActionsSupportedDebounceTicks,
	}
}

// selectActuator picks Phorvex's hands: the native actuator (its own client-go hands,
// PHORVEX_ACTUATOR=native) or the Phoenix adapter (default — drives UNMODIFIED Phoenix via
// SecurityEvent/AMTD CRs). Both satisfy the Actuator interface; the brain is unchanged.
func selectActuator(c client.Client, log logr.Logger) actuator.Actuator {
	switch os.Getenv("PHORVEX_ACTUATOR") {
	case "native":
		log.WithName("runner").Info("actuator=native (Phorvex own hands; direct client-go enactment, no Phoenix CRDs)")
		return actuator.NewNativeActuator(c)
	case "hybrid":
		// Phoenix enacts rotate/quarantine (keeps the nats AMTD-CR mechanism); the native
		// actuator enacts the AI-native moves (kv-reset, adapter-rotate, …) Phoenix can't.
		log.WithName("runner").Info("actuator=hybrid (Phoenix for rotate/quarantine, native for AI-native moves)")
		return actuator.NewHybridActuator(c)
	default:
		return actuator.NewPhoenixActuator(c)
	}
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
	unsupportedTicks := 0
	unsupportedSignature := ""
	if existing != nil {
		last = existing.lastTick
		if existing.generation == p.Generation {
			unsupportedTicks = existing.actionsUnsupportedTicks
			unsupportedSignature = existing.actionsUnsupportedSignature
		}
	}
	m.policies[key.String()] = &policyEntry{
		key:       key,
		uid:       string(p.UID),
		tenant:    p.EffectiveTenant(),
		namespace: p.Namespace,
		spec:      *p.Spec.DeepCopy(),
		selector:  sel,
		lastTick:  last,

		generation:                  p.Generation,
		actionsUnsupportedTicks:     unsupportedTicks,
		actionsUnsupportedSignature: unsupportedSignature,
	}
	return nil
}

// Remove drops a tenant policy and clears its metric series.
func (m *Manager) Remove(key types.NamespacedName) {
	m.mu.Lock()
	e := m.policies[key.String()]
	delete(m.policies, key.String())
	delete(m.emits, key.String())
	m.mu.Unlock()
	if e != nil {
		metrics.ResetTenant(e.tenant)
		metrics.ResetKillSwitchStatus(e.key.Namespace, e.key.Name)
	}
}

// recordEmits appends n enacted moves at now to the policy's ledger, drops entries older
// than the trailing window and returns how many enacted moves remain inside it. Called
// exactly once per tick, OUTSIDE the status conflict-retry loop, so a retried write never
// double-counts. Selected-but-not-emitted decisions (dry-run, kill-switch, actuator
// failure) are never recorded.
func (m *Manager) recordEmits(key string, n int, now time.Time, window time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.emits == nil {
		m.emits = map[string][]time.Time{}
	}
	ledger := m.emits[key]
	for i := 0; i < n; i++ {
		ledger = append(ledger, now)
	}
	cutoff := now.Add(-window)
	kept := ledger[:0]
	for _, ts := range ledger {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) == 0 {
		delete(m.emits, key)
		return 0
	}
	m.emits[key] = kept
	return len(kept)
}

// NeedLeaderElection keeps the mutating tick loop in controller-runtime's
// leader-elected runnable group. Without this method every replica starts the
// loop even when the manager itself has leader election enabled.
func (*Manager) NeedLeaderElection() bool { return true }

// Start implements manager.Runnable: it runs the tick loop until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) error {
	// The exact-optimality claim depends on block-disjoint cover keys. Validate every
	// registered recon profile once, before starting the sub-second tick path.
	if err := recon.ValidateRegistryCoverKeys(); err != nil {
		return fmt.Errorf("recon cover-key startup invariant failed: %w", err)
	}
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

	// [PHVX-2] Online cost calibration has its own off-switch, evaluated every tick from the same
	// sentinel ConfigMap so it takes effect without a restart. `ok=false` means the sentinel could
	// not be read; hold the current state rather than discard every tenant's calibration on a
	// transient API error.
	if frozen, ok := m.KillSwitch.CalibrationFrozen(ctx); ok {
		if ce, isCoverage := m.Optimizer.(*decision.CoverageEngine); isCoverage {
			ce.SetCostCalibrationFrozen(frozen)
		}
	}

	// [PHVX-10c] Publish calibrator state after applying the switch, including explicit zeroes when
	// a tenant's pending queue drains. Without the zero update, the gauge remains stuck at its last
	// nonzero value forever.
	m.publishRLSMetrics()

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

	calibrationDue := m.Calibration != nil && m.Calibration.Due(now)
	if len(due) == 0 && !calibrationDue {
		return
	}

	var ownerReader client.Reader
	if m.Actuator != nil && m.Actuator.Name() == "native" {
		ownerReader = m.OwnershipReader
	}
	snap, err := ingest.CollectSnapshotForRotationTargets(ctx, m.Client, now, genericAssetValue, ownerReader, func(p *corev1.Pod) bool {
		for _, e := range due {
			if p.Namespace == e.namespace && (e.selector == nil || e.selector.Matches(labels.Set(p.Labels))) {
				return true
			}
		}
		return false
	})
	if err != nil {
		m.Log.Error(err, "ingest snapshot failed; skipping tick")
		return
	}

	m.observeEventTrust(snap.Events)

	// GPU-half physics on the LIVE tick (not just --scan): fill the DCGM-via-Prometheus witness so
	// VRAMFraction/SMOccupancy/LinkBandwidth/GPUPresent feed the live decision engine when a Prometheus
	// feed is wired. Honest-absent (leaves the neutral witness) when PromURL is empty or DCGM has no data.
	if m.PromURL != "" {
		ingest.PopulateGPUWitness(ctx, snap, m.PromURL, m.PCIeClasses)
	}

	// Complete post-action feedback before making this tick's decisions. This is
	// non-blocking: recovery is measured from the Kubernetes snapshots the runner
	// already collects, never by waiting inside Actuate.
	m.observeReadyRotations(snap)

	// Derive the full-cluster witness once. It is shared by every tenant and by the
	// shadow calibrator; repeated derivation would make refresh cost grow with tenant count.
	_, physicsByKey := platform.Derive(snap)
	if calibrationDue {
		if _, _, err := m.Calibration.ObserveSnapshot(snap, physicsByKey); err != nil {
			m.Log.Error(err, "shadow calibration export failed; metrics and in-memory result remain available")
		}
	}

	for _, e := range due {
		m.processTenantWithPhysics(ctx, snap, e, killEngaged, physicsByKey)
	}
}

func (m *Manager) publishRLSMetrics() {
	pendingByTenant := map[string]int{}
	for _, p := range m.pendingRotations {
		pendingByTenant[p.tenant]++
	}

	if ce, isCoverage := m.Optimizer.(*decision.CoverageEngine); isCoverage {
		for tenant, st := range ce.CalibrationState() {
			metrics.SetRLSState(tenant, st.Primed, st.Updates)
			metrics.SetRotationsPending(tenant, pendingByTenant[tenant])
			delete(pendingByTenant, tenant)
		}
	}
	// A pending rotation can be registered before its tenant bucket is visible. Publish those too;
	// they will move through the calibrated-state loop on subsequent ticks.
	for tenant, n := range pendingByTenant {
		metrics.SetRotationsPending(tenant, n)
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

func rotationObservationKey(tenant string, view *model.WorkloadView) string {
	return tenant + "\x00" + view.Pod.Namespace + "\x00" + view.Pod.UID
}

// trackRotation records only controller-owned rotations for optimizers that can
// consume feedback. Without a controller identity there is no honest way to match
// a replacement, so the observation remains unavailable rather than fabricated.
func (m *Manager) trackRotation(tenant string, view *model.WorkloadView, allViews map[string]*model.WorkloadView, startedAt time.Time) bool {
	return m.trackRotationWithFloor(tenant, view, allViews, -1, startedAt)
}

// trackRotationWithFloor freezes the service's availability threshold at action
// start so the disruption ledger can record breach-seconds separately from
// replica-seconds. A negative floor means the threshold was unavailable.
func (m *Manager) trackRotationWithFloor(tenant string, view *model.WorkloadView, allViews map[string]*model.WorkloadView, minAvailableReplicas int, startedAt time.Time) bool {
	_, costObserver := m.Optimizer.(decision.RotationObserver)
	if (!costObserver && m.Calibration == nil && m.Disruption == nil) || view == nil {
		return false
	}
	if view.Pod.OwnerKind == "" || view.Pod.OwnerName == "" || view.Pod.UID == "" {
		if m.Calibration != nil {
			m.Calibration.ObserveRotation(calib.RotationRecord{
				ID:     fmt.Sprintf("%s/%s/%s@%d", tenant, view.Pod.Namespace, view.Pod.Name, startedAt.UnixNano()),
				Tenant: tenant, Namespace: view.Pod.Namespace, Pod: view.Pod.Name, Action: string(model.ActionRotate),
				StartedAt: startedAt, RecordedAt: startedAt, Outcome: calib.OutcomeInvalid,
				InvalidReason:    "controller owner or pod UID unavailable; replacement cannot be matched",
				ReferenceAtStart: cost.ReadyDelayReference,
				CensorDeadline:   startedAt.Add(2 * cost.ReadyDelayReference),
			})
		}
		return false
	}
	known := map[string]struct{}{}
	for _, other := range allViews {
		if other.Pod.Namespace == view.Pod.Namespace && other.Pod.OwnerKind == view.Pod.OwnerKind &&
			other.Pod.OwnerName == view.Pod.OwnerName && other.Pod.UID != "" {
			known[other.Pod.UID] = struct{}{}
		}
	}
	if m.pendingRotations == nil {
		m.pendingRotations = map[string]pendingRotation{}
	}
	key := rotationObservationKey(tenant, view)
	if _, alreadyPending := m.pendingRotations[key]; alreadyPending {
		return true // repeated Phoenix emits must not reset the original recovery clock
	}
	m.pendingRotations[key] = pendingRotation{
		tenant: tenant, startedAt: startedAt,
		referenceAtStart:     cost.ReadyDelayReference,
		censorDeadline:       startedAt.Add(2 * cost.ReadyDelayReference),
		view:                 *view,
		knownUIDs:            known,
		minAvailableReplicas: minAvailableReplicas,
		selectionBound:       selectionBound(model.ActionRotate),
	}
	return true
}

func selectionBound(action model.Action) slo.Bound {
	if bound, ok := slo.Classify(action); ok {
		return bound
	}
	return slo.Bound{
		Action: action, Status: slo.StatusUnknown,
		MissingBound: "action has no deterministic-impact classification",
	}
}

func selectionBoundEvidence(bound slo.Bound) string {
	if bound.MissingBound == "" {
		return bound.Evidence
	}
	if bound.Evidence == "" {
		return bound.MissingBound
	}
	return bound.Evidence + "; missing: " + bound.MissingBound
}

// recordActionOutcome retains every actuation outcome for which the runner has a
// terminal synchronous result. Non-zero actions are explicitly unmeasured here:
// a return from Actuate does not prove that asynchronous serving impact ended.
// Rotate is recorded by observeReadyRotations instead, when recovery is observed.
func (m *Manager) recordActionOutcome(tenant string, view *model.WorkloadView, action model.Action, minAvailableReplicas int, startedAt, observedAt time.Time, outcome slo.Outcome) {
	if m.Disruption == nil || view == nil {
		return
	}
	bound := selectionBound(action)
	boundValue, boundFinite := bound.ReplicaSeconds()
	impact := slo.ImpactUnmeasured
	availabilityMeasured := false
	if bound.Status == slo.StatusZero {
		impact = slo.ImpactMeasured
		availabilityMeasured = true
	}
	duration := observedAt.Sub(startedAt)
	if duration < 0 {
		duration = 0
	}
	m.Disruption.Record(slo.Entry{
		ID:     fmt.Sprintf("%s/%s/%s/%d", tenant, view.Pod.Namespace+"/"+view.Pod.Name, action, startedAt.UnixNano()),
		Tenant: tenant, Namespace: view.Pod.Namespace, Pod: view.Pod.Name,
		Action: action, Cause: slo.CausePhorvex, Outcome: outcome,
		Duration: duration, StartedAt: startedAt, ObservedAt: observedAt,
		ReplicaImpact:        impact,
		SelectionBoundStatus: bound.Status, SelectionBoundFinite: boundFinite,
		SelectionBoundReplicaSeconds: boundValue, SelectionBoundEvidence: selectionBoundEvidence(bound),
		ReadyReplicasBefore: view.Pod.ReadyReplicas, MinAvailableReplicas: minAvailableReplicas,
		AvailabilityMeasured: availabilityMeasured,
	})
}

// observeReadyRotations resolves pending rotations one-to-one against new Ready
// UIDs owned by the same controller. At two reference windows an unresolved
// recovery produces one truthful right-censored RLS outcome (C_flow=2). When the
// disruption ledger is enabled, tracking continues so an outage lasting longer
// than that modelling window is not permanently undercounted at 800 seconds.
func (m *Manager) observeReadyRotations(snap *ingest.Snapshot) {
	observer, costObserver := m.Optimizer.(decision.RotationObserver)
	if (!costObserver && m.Calibration == nil && m.Disruption == nil) || snap == nil || len(m.pendingRotations) == 0 {
		return
	}
	type pendingRef struct {
		key string
		p   pendingRotation
	}
	pending := make([]pendingRef, 0, len(m.pendingRotations))
	for key, p := range m.pendingRotations {
		pending = append(pending, pendingRef{key: key, p: p})
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].p.startedAt.Equal(pending[j].p.startedAt) {
			return pending[i].key < pending[j].key
		}
		return pending[i].p.startedAt.Before(pending[j].p.startedAt)
	})

	claimed := map[string]bool{}
	for _, ref := range pending {
		p := ref.p
		oldUIDPresent := false
		for i := range snap.Pods {
			if snap.Pods[i].UID == p.view.Pod.UID {
				oldUIDPresent = true
				break
			}
		}
		elapsed := snap.Now.Sub(p.startedAt)
		if oldUIDPresent {
			// Phoenix reports that the SecurityEvent was emitted, not that Delete
			// executed. Never train on a scale-up/rollout while the target UID is
			// still alive. Retire an unexecuted event after the observation window.
			if !snap.Now.Before(p.censorDeadline) {
				delete(m.pendingRotations, ref.key)
				// The actuation never took effect — the target is still alive. Nothing is learned,
				// and this is a DIFFERENT failure from "no replacement became Ready" (PHVX-10c).
				if costObserver {
					metrics.ObserveRotationOutcome(p.tenant, metrics.RLSAbandoned)
				}
				if m.Calibration != nil {
					m.Calibration.ObserveRotation(calib.RotationRecord{
						ID: ref.key, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
						Action: string(model.ActionRotate), StartedAt: p.startedAt, RecordedAt: snap.Now,
						Elapsed: elapsed, Outcome: calib.OutcomeInvalid,
						InvalidReason:    "original pod UID remained present through the observation deadline",
						ReferenceAtStart: p.referenceAtStart, CensorDeadline: p.censorDeadline,
					})
				}
				m.Log.Info("rotation cost observation unavailable; original UID still present",
					"tenant", p.tenant,
					"pod", p.view.Pod.Namespace+"/"+p.view.Pod.Name,
					"oldUID", p.view.Pod.UID)
			}
			continue
		}
		var replacement *model.Pod
		for i := range snap.Pods {
			candidate := &snap.Pods[i]
			if !candidate.Ready || candidate.UID == "" || claimed[candidate.UID] ||
				candidate.Namespace != p.view.Pod.Namespace ||
				candidate.OwnerKind != p.view.Pod.OwnerKind || candidate.OwnerName != p.view.Pod.OwnerName {
				continue
			}
			if _, existed := p.knownUIDs[candidate.UID]; existed {
				continue
			}
			// Kubernetes serializes Pod condition transition timestamps at whole-second
			// precision, while startedAt carries Go nanoseconds. Compare at the API's
			// precision so a genuine sub-second replacement in the SAME timestamp second
			// is not misclassified as predating the actuation. knownUIDs above still
			// excludes every pod present in the pre-action snapshot.
			if !candidate.ReadyAt.IsZero() &&
				candidate.ReadyAt.Truncate(time.Second).Before(p.startedAt.Truncate(time.Second)) {
				continue
			}
			if replacement == nil || candidate.ReadyAt.Before(replacement.ReadyAt) ||
				(candidate.ReadyAt.Equal(replacement.ReadyAt) && candidate.UID < replacement.UID) {
				replacement = candidate
			}
		}

		calibrationCensored := false
		ledgerCensored := false
		observationEnd := snap.Now
		if replacement != nil {
			claimed[replacement.UID] = true
			if !replacement.ReadyAt.IsZero() {
				elapsed = replacement.ReadyAt.Sub(p.startedAt)
				observationEnd = replacement.ReadyAt
				calibrationCensored = replacement.ReadyAt.After(p.censorDeadline)
			}
		} else if !snap.Now.Before(p.censorDeadline) {
			calibrationCensored = true
			ledgerCensored = true
		} else {
			continue
		}
		if elapsed < 0 {
			elapsed = 0
		}
		calibrationElapsed := elapsed
		if calibrationCensored {
			calibrationElapsed = p.censorDeadline.Sub(p.startedAt)
			if calibrationElapsed < 0 {
				calibrationElapsed = 0
			}
		}
		newOutcome := !p.costObserved && (costObserver || m.Calibration != nil)
		if newOutcome {
			measuredFlow := (calib.RotationRecord{
				Elapsed: calibrationElapsed, ReferenceAtStart: p.referenceAtStart,
			}).Normalized()
			if costObserver {
				observer.ObserveRotation(p.tenant, &p.view, measuredFlow)
			}
			if m.Calibration != nil {
				calibrationOutcome := calib.OutcomeObserved
				if calibrationCensored {
					calibrationOutcome = calib.OutcomeCensored
				}
				record := calib.RotationRecord{
					ID: ref.key, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
					Action: string(model.ActionRotate), StartedAt: p.startedAt,
					Elapsed: calibrationElapsed, Outcome: calibrationOutcome,
					ReferenceAtStart: p.referenceAtStart, CensorDeadline: p.censorDeadline,
				}
				if calibrationCensored {
					record.RecordedAt = p.censorDeadline
				} else if replacement != nil && !replacement.ReadyAt.IsZero() {
					record.ReadyAt = replacement.ReadyAt
					record.RecordedAt = replacement.ReadyAt
				}
				m.Calibration.ObserveRotation(record)
			}
			// The RLS outcome is recorded once. A censored rotation can remain in the
			// pending map for ledger updates without inflating the match-rate denominator.
			if costObserver {
				outcome := metrics.RLSMatched
				if calibrationCensored {
					outcome = metrics.RLSCensored
				}
				metrics.ObserveRotationOutcome(p.tenant, outcome)
			}
			p.costObserved = true
			m.pendingRotations[ref.key] = p
		}
		// The same measurement, in the SLO's unit. A rotation removes exactly one
		// Ready serving replica (feasibility.RemovesReadyReplica) and `elapsed` is
		// how long it stayed removed, so this is one unavailable-replica-second
		// reading — measured, not modelled. Censored readings are kept and marked:
		// discarding them would understate consumption exactly when recovery was
		// worst. Abandoned rotations are excluded, above, because nothing was ever
		// removed and so nothing was consumed.
		if m.Disruption != nil {
			availabilityMeasured := p.minAvailableReplicas >= 0 && p.view.Pod.ReadyReplicas > 0
			breachDuration := time.Duration(0)
			breachStartedAt, breachObservedAt := time.Time{}, time.Time{}
			if availabilityMeasured && p.view.Pod.ReadyReplicas-1 < p.minAvailableReplicas {
				breachDuration = elapsed
				breachStartedAt, breachObservedAt = p.startedAt, observationEnd
			}
			boundValue, boundFinite := p.selectionBound.ReplicaSeconds()
			outcome := slo.OutcomeCompleted
			if ledgerCensored {
				outcome = slo.OutcomeRightCensored
			}
			m.Disruption.Record(slo.Entry{
				ID:                           ref.key,
				Tenant:                       p.tenant,
				Namespace:                    p.view.Pod.Namespace,
				Pod:                          p.view.Pod.Name,
				Action:                       model.ActionRotate,
				Cause:                        slo.CausePhorvex,
				Replicas:                     1,
				Duration:                     elapsed,
				StartedAt:                    p.startedAt,
				ObservedAt:                   observationEnd,
				Censored:                     ledgerCensored,
				Outcome:                      outcome,
				ReplicaImpact:                slo.ImpactMeasured,
				SelectionBoundStatus:         p.selectionBound.Status,
				SelectionBoundFinite:         boundFinite,
				SelectionBoundReplicaSeconds: boundValue,
				SelectionBoundEvidence:       selectionBoundEvidence(p.selectionBound),
				ReadyReplicasBefore:          p.view.Pod.ReadyReplicas,
				MinAvailableReplicas:         p.minAvailableReplicas,
				AvailabilityMeasured:         availabilityMeasured,
				AvailabilityBreachDuration:   breachDuration,
				AvailabilityBreachStartedAt:  breachStartedAt,
				AvailabilityBreachObservedAt: breachObservedAt,
			})
		}
		if ledgerCensored {
			if m.Disruption == nil {
				delete(m.pendingRotations, ref.key)
			}
			if newOutcome && costObserver {
				m.Log.Info("rotation cost observation censored; disruption tracking continues",
					"tenant", p.tenant,
					"pod", p.view.Pod.Namespace+"/"+p.view.Pod.Name,
					"oldUID", p.view.Pod.UID,
					"timeUnavailableSeconds", elapsed.Seconds())
			}
			continue
		}
		delete(m.pendingRotations, ref.key)
		replacementUID := ""
		if replacement != nil {
			replacementUID = replacement.UID
		}
		m.Log.Info("rotation cost observation applied",
			"tenant", p.tenant,
			"pod", p.view.Pod.Namespace+"/"+p.view.Pod.Name,
			"oldUID", p.view.Pod.UID,
			"replacementUID", replacementUID,
			"timeToReadySeconds", elapsed.Seconds(),
			"calibrationCensored", calibrationCensored)
	}
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
	_, physicsByKey := platform.Derive(snap)
	m.processTenantWithPhysics(ctx, snap, e, killEngaged, physicsByKey)
}

func (m *Manager) processTenantWithPhysics(ctx context.Context, snap *ingest.Snapshot, e *policyEntry, killEngaged bool, physicsByKey map[string]model.PhysicsWitness) {
	start := time.Now()
	pol := buildPolicy(e)
	pol.NativeRotate = m.Actuator != nil && m.Actuator.Name() == "native"
	pol.TraceEnabled = m.DecisionTraceEnabled
	pol.BrainImage = m.BrainImage
	pol.GitSHA = m.GitSHA
	pol.TickID = deterministicTraceID("tick", snap.Now.UTC().Format(time.RFC3339Nano), pol.PolicyUID, pol.Tenant)

	// P-PHYSICS (UCW): the caller derives one discovered witness map for the shared snapshot.
	// Honest-absent (NeutralPhysics) when no scan answers.
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
		// M-130/M-113: use the BEST-EFFORT map even on a partial scrape failure (dropping the
		// whole tick's telemetry was the silent-outage bug). A source failure is surfaced as a
		// metric + an error log, and per-signal State=Error keeps absence distinguishable.
		t, err := m.MetricsSource.PodMetrics(ctx, e.namespace, names)
		if t != nil {
			tele = t
		}
		m.observeSourceHealth(e, err)
	}

	pol.DecisionAssets = map[string]string{}
	for _, pod := range selPods {
		pol.DecisionAssets[pod.Namespace+"/"+pod.Name] = pod.UID
	}
	for _, ev := range snap.Events {
		if len(ev.Outcomes) > 0 {
			pol.TrustBoundaryReason = "uncached-boundary-reader-unavailable"
			if m.BoundaryReader != nil {
				boundaryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				pol.TrustBoundaryReady, pol.TrustBoundaryReason, pol.TrustBoundarySince = ingest.CheckExistentialBoundary(boundaryCtx, m.BoundaryReader)
				cancel()
			}
			break
		}
	}
	keep := make(map[string]struct{}, len(selPods))
	views := make([]*model.WorkloadView, 0, len(selPods))
	for _, p := range selPods {
		t := tele[p.Name]
		// M-23: one fingerprint per CLOCKED exposure variable — pod identity, session,
		// plus the per-action `*-epoch` markers (absent-skipped when a marker is missing). The
		// [PHVX-67] session clock still resets when either KV flush bumps p.SessionEpoch.
		m.Clock.Observe(exposure.Observation{
			Tenant:       pol.Tenant,
			Namespace:    p.Namespace,
			Pod:          p.Name,
			StartedAt:    p.StartedAt,
			Fingerprints: model.ExposureFingerprints(*p),
		}, snap.Now)
		keep[exposure.SlotKey(pol.Tenant, p.Namespace, p.Name)] = struct{}{}
		exp := m.Clock.Since(pol.Tenant, p.Namespace, p.Name, snap.Now)
		// Per-action emit intent (M-23): the most recent EMISSION per variable, stamped at the
		// emit boundary before the observed epoch catches up. The guard takes min(exp, intent).
		intent := m.Intents.Since(pol.Tenant, p.Namespace, p.Name, snap.Now)

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
		viewPod := *p
		viewPod.RouteServiceReady = declaredRouteServiceExists(p, snap.Services)
		if pol.P99Ms > 0 && !t.P99Ms.Usable() {
			// SLO latency headroom unmeasurable: the gate is skipped (never blocks, P-NO-FREEZE)
			// and counted, instead of passing as a silent full-headroom 1.0 (B-3).
			metrics.RecordSLOGateSkipped(pol.Tenant, t.P99Ms.State.String())
		}
		views = append(views, &model.WorkloadView{
			Pod:                viewPod,
			Telemetry:          t,
			Phase:              ingest.PhaseOf(*p, t),
			PhaseReason:        ingest.PhaseReasonOf(*p, t),
			BlastRadius:        snap.Graph.BlastRadius(p.Namespace, p.Name),
			NeighborCount:      snap.Graph.NeighborCount(p.Namespace, p.Name),
			Neighbors:          neighbors,
			Events:             events,
			OutcomeEvents:      snap.Events,
			ExposureByVariable: exp,
			IntentByVariable:   intent,
			Physics:            ph,
			InfectionFrontier:  infectionFrontier(nbKeys, infected),
		})
	}
	// T1-E: build ONE per-tick capability witness (the single predicate home) and use it
	// for BOTH the ActionsSupported status (capability leg only, via Capable) AND the
	// generator's pre-scoring gate (full Eligible incl. installability + RBAC) — so the
	// two can never drift into the M-20 mirror. m.Authz is nil until the boot layer wires
	// the SSAR checker (then no-rbac becomes live); NotInstallable is empty on a current
	// CRD (17/17).
	capWit := capability.BuildWitness(ctx, capability.BuildIndex(snap.Pods, snap.Nodes, snap.Services), model.NotInstallable, m.Authz, m.Actuator)
	actionsSupport := m.debounceActionsSupported(e, capabilityGaps(pol, views, capWit))
	if ce, ok := m.Optimizer.(*decision.CoverageEngine); ok {
		ce.Capability = func(v *model.WorkloadView, a model.Action, coverKeys []string) *actionset.Eligibility {
			r := capWit.Eligible(v, a, coverKeys)
			if r == nil {
				if m.Authz == nil && decision.HasQualifiedOutcome(v, pol) {
					return &actionset.Eligibility{Excluded: true, Kind: capability.ReasonNoRBAC, Detail: "m99: RBAC checker unavailable"}
				}
				return nil
			}
			return &actionset.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
		}
	}

	var shadowDecisions []model.Decision
	shadowAvailable := false
	if m.Calibration != nil {
		if shadowViews, ok := m.Calibration.ShadowViews(views); ok {
			if shadow, supported := m.Optimizer.(decision.ShadowCheckedOptimizer); supported {
				var shadowErr error
				shadowDecisions, shadowErr = shadow.DecideShadowChecked(shadowViews, pol)
				shadowAvailable = shadowErr == nil
				if shadowErr != nil {
					m.Log.Error(shadowErr, "shadow scale optimizer comparison unavailable", "tenant", pol.Tenant)
				}
			}
		}
	}

	decisions, err := decideTick(m.Optimizer, views, pol)
	if err != nil {
		metrics.RecordActionSetRejection(pol.Tenant, "cross-block-collision")
		m.Log.Error(err, "action set rejected; decisions and actuation suppressed for tick",
			"tenant", pol.Tenant, "optimizer", m.Optimizer.Name())
		rejected := decision.ExistentialRejectedDecisions(views, pol, err.Error(), snap.Now)
		for _, d := range rejected {
			m.Audit.Record(d)
		}
		inventory := outcomeInventory(snap.Events, pol)
		if inventory != nil {
			m.Audit.RecordOutcomeInventory(pol.Tenant, snap.Now, inventory)
		}
		if len(rejected) > 0 || inventory != nil {
			m.updateExistentialStatus(ctx, e, rejected, inventory)
		}
		m.Clock.RetainTenant(pol.Tenant, keep)
		m.Intents.RetainTenant(pol.Tenant, keep) // M-23: GC emit intent with the exposure clock
		if ce, ok := m.Optimizer.(*decision.CoverageEngine); ok {
			ce.RetainStageClock(pol.Tenant, keep)
		}
		m.mu.Lock()
		if cur := m.policies[e.key.String()]; cur != nil {
			cur.lastTick = snap.Now
		}
		m.mu.Unlock()
		return
	}
	if shadowAvailable {
		availabilityViolations, sloViolations := shadowSafetyViolations(shadowDecisions, views, pol)
		m.Calibration.ObserveValidation(calib.SelectionComparison{
			At:               snap.Now,
			Tenant:           pol.Tenant,
			Production:       selectedDecisionKeys(decisions),
			Shadow:           selectedDecisionKeys(shadowDecisions),
			ProductionScores: decisionScores(decisions),
			ShadowScores:     decisionScores(shadowDecisions),
		}, availabilityViolations, sloViolations)
	}

	// Effective actuation gate (FR8): a tenant is dry-run if its policy says so OR its
	// namespace is annotated phorvex.ai/dry-run; the global kill-switch suppresses on top.
	nsDryRun := snap.DryRunNamespaces[e.namespace]
	effectiveDryRun := pol.DryRun || nsDryRun
	if effectiveDryRun {
		for i := range decisions {
			decisions[i].DryRun = true // honest audit: reflect the mode actually applied
			if decisions[i].Trace != nil {
				decisions[i].Trace.DryRun = true
				// T0-C: actuate() never runs under dry-run — a selected move is
				// not-attempted for that reason, not silently un-dispatched.
				if decisions[i].Selected {
					decisions[i].Trace.DispatchOutcome = model.DispatchNotAttempted
					decisions[i].Trace.DispatchReason = "dry-run"
				}
			}
		}
	}
	if killEngaged {
		for i := range decisions {
			// The kill switch is a SEPARATE gate from dry-run: it leaves DryRun false while
			// suppressing actuation. Stamping it keeps a decision-only mirror (an operator
			// run with --global-kill-switch to feed a dashboard) distinguishable from an
			// operator whose actuator is failing. Both otherwise emit the identical record.
			decisions[i].KillSwitch = true
			if decisions[i].Trace != nil {
				decisions[i].Trace.KillSwitchEngaged = true
				if decisions[i].Selected {
					decisions[i].Trace.DispatchOutcome = model.DispatchNotAttempted
					decisions[i].Trace.DispatchReason = "kill-switch"
				}
			}
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

	assessmentInput := colocationInput(snap, e)
	selected, infeasible := 0, 0
	claim := model.NewClaimScope(ingest.EventTrust().List(), true, m.BrainImage, m.GitSHA)
	for i := range decisions {
		decisions[i].Claim = &claim
		m.Audit.Record(decisions[i])
		m.recordColocation(assessmentInput, decisions[i], pol)
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
	metrics.PublishTick(pol.Tenant, pol.PolicyName, decisions, exposuresForMetrics, selected, dur.Seconds(), pol.Mode)
	m.Audit.TickSummary(pol.Tenant, len(decisions), selected, infeasible, dur, pol.Mode, killEngaged)
	m.Clock.RetainTenant(pol.Tenant, keep)
	m.Intents.RetainTenant(pol.Tenant, keep) // M-23: GC emit intent with the exposure clock
	if ce, ok := m.Optimizer.(*decision.CoverageEngine); ok {
		ce.RetainStageClock(pol.Tenant, keep)
	}
	inventory := outcomeInventory(snap.Events, pol)
	if inventory != nil {
		m.Audit.RecordOutcomeInventory(pol.Tenant, snap.Now, inventory)
	}
	m.updateExistentialStatus(ctx, e, decisions, inventory)
	m.updateStatus(ctx, e, len(views), selected, actuated, killEngaged, snap.Now, actionsSupport)

	m.mu.Lock()
	if cur := m.policies[e.key.String()]; cur != nil {
		cur.lastTick = snap.Now
	}
	m.mu.Unlock()
}

func declaredRouteServiceExists(p *model.Pod, services []ingest.ServiceInfo) bool {
	if p == nil || p.RouteService == "" {
		return false
	}
	for _, service := range services {
		if service.Namespace == p.Namespace && service.Name == p.RouteService {
			return true
		}
	}
	return false
}

func decideTick(optimizer decision.Optimizer, views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error) {
	if checked, ok := optimizer.(decision.CheckedOptimizer); ok {
		return checked.DecideChecked(views, pol)
	}
	return optimizer.Decide(views, pol), nil
}

func selectedDecisionKeys(decisions []model.Decision) []string {
	keys := make([]string, 0, len(decisions))
	for _, d := range decisions {
		if d.Selected {
			keys = append(keys, d.Namespace+"/"+d.Pod+":"+string(d.Action))
		}
	}
	sort.Strings(keys)
	return keys
}

func decisionScores(decisions []model.Decision) []calib.DecisionScore {
	scores := make([]calib.DecisionScore, 0, len(decisions))
	for _, d := range decisions {
		scores = append(scores, calib.DecisionScore{
			Key: d.Namespace + "/" + d.Pod, Action: string(d.Action), Selected: d.Selected,
			CoverageValue: d.CoverageValue, Cost: d.Cost, Net: d.Net,
		})
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i].Key < scores[j].Key })
	return scores
}

func shadowSafetyViolations(decisions []model.Decision, views []*model.WorkloadView, pol model.Policy) (availability, slo int) {
	viewByKey := make(map[string]*model.WorkloadView, len(views))
	for _, view := range views {
		if view != nil {
			viewByKey[view.Pod.Namespace+"/"+view.Pod.Name] = view
		}
	}
	for _, d := range decisions {
		if !d.Selected {
			continue
		}
		view := viewByKey[d.Namespace+"/"+d.Pod]
		if view == nil {
			availability++
			continue
		}
		verdict := feasibility.Evaluate(view, model.Move{Action: d.Action}, pol)
		if verdict.Feasible {
			continue
		}
		switch {
		case strings.HasPrefix(verdict.Reason, "slo:"), strings.HasPrefix(verdict.Reason, "tokens/sec"):
			slo++
		default:
			availability++
		}
	}
	return availability, slo
}

func (m *Manager) actuate(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, tickViewByKey map[string]*model.WorkloadView) int {
	target := actuator.TenantTarget{
		Tenant:         pol.Tenant,
		Namespace:      e.namespace,
		MatchLabels:    e.spec.Selector.MatchLabels,
		EnabledActions: pol.EnabledActions,
	}
	if err := m.Actuator.EnsurePolicy(ctx, target); err != nil {
		m.Log.Error(err, "actuator EnsurePolicy failed; suppressing actuation this tick", "tenant", pol.Tenant)
		// T0-C: a tick-level pre-dispatch guard — every selected move is refused here.
		for i := range decisions {
			if decisions[i].Selected && decisions[i].Trace != nil {
				decisions[i].Trace.DispatchOutcome = model.DispatchNotAttempted
				decisions[i].Trace.DispatchReason = "ensure-policy-failed"
			}
		}
		return 0
	}
	actuated := 0
	for i := range decisions {
		if !decisions[i].Selected {
			continue
		}
		// T0-C: every guard below stamps the dispatch outcome on the trace before
		// the audit write, so a selected-but-refused move never reads as unselected.
		stampDispatch := func(outcome, reason string) {
			if decisions[i].Trace != nil {
				decisions[i].Trace.DispatchOutcome = outcome
				decisions[i].Trace.DispatchReason = reason
			}
		}
		// Inviolability guard at the emit boundary (defense in depth): a selected move is
		// ALWAYS feasible (the action-set generator excluded infeasible moves before
		// selection), but never emit one that is not — and shout if the invariant breaks.
		if !decisions[i].Feasible || decisions[i].Action == model.ActionNoop {
			m.Log.Error(nil, "INVARIANT VIOLATION: a selected move was infeasible/noop; refusing to emit",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			stampDispatch(model.DispatchNotAttempted, "inviolability-guard")
			continue
		}
		// Same-tick invariant check: evaluate the selected action against the same tick snapshot
		// that fed the generator. This catches an internal decision/view mismatch and is uniform
		// across native actions, but it does not refresh Kubernetes state or claim to close the
		// snapshot-to-actuation race. Live mutation safety belongs to the actuator's fresh Get,
		// resourceVersion and UID preconditions.
		//
		// [P4c D3/F5 FAIL-CLOSED FIX] A MISSING tick view for the target is UNCERTAINTY, not a
		// pass: previously the check ran only inside `; ok {`, so a map-miss SKIPPED the gate
		// (fail-OPEN) and actuated on the stale cached bool. Now a map-miss VETOES (fail-CLOSED):
		// we never actuate a move whose target is absent from the tick snapshot.
		v, ok := tickViewByKey[decisions[i].Namespace+"/"+decisions[i].Pod]
		if !ok {
			m.Log.Error(nil, "EMIT-BOUNDARY VETO (fail-closed): no tick view for the target; refusing to actuate",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			stampDispatch(model.DispatchNotAttempted, "no-tick-view")
			continue
		}
		if verdict := existentialEmitVerdict(decisions[i], v, pol); !verdict.Feasible {
			m.Log.Error(nil, "EMIT-BOUNDARY INVARIANT VETO: refusing infeasible move at actuate boundary",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action, "reason", verdict.Reason)
			stampDispatch(model.DispatchNotAttempted, "emit-boundary-infeasible: "+verdict.Reason)
			continue
		}
		score := -1.0
		var coverageValue *float64
		if decisions[i].Engine == "p0-greedy" {
			score = decisions[i].ThreatRisk
			if score > 1 {
				score = 1
			}
		} else {
			value := decisions[i].CoverageValue
			coverageValue = &value
		}
		actuationStarted := time.Now()
		recordExistentialEffect(&decisions[i], true)
		res, err := m.Actuator.Actuate(ctx, actuator.Request{
			Tenant:        pol.Tenant,
			Namespace:     decisions[i].Namespace,
			Pod:           decisions[i].Pod,
			Action:        decisions[i].Action,
			Reason:        decisions[i].Reason,
			Score:         score,
			CoverageValue: coverageValue,
			TargetUID:     v.Pod.UID,
		})
		if err != nil {
			outcome := slo.OutcomeFailed
			dispatchReason := "failed"
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				outcome = slo.OutcomeDeadlineExpired
				dispatchReason = "deadline-expired"
			}
			stampDispatch(model.DispatchError, dispatchReason)
			m.recordActionOutcome(pol.Tenant, v, decisions[i].Action, pol.MinAvailableReplicas, actuationStarted, time.Now(), outcome)
			m.Log.Error(err, "actuate failed", "pod", decisions[i].Namespace+"/"+decisions[i].Pod)
			continue
		}
		if res.Emitted {
			stampDispatch(model.DispatchEmitted, res.Note)
			decisions[i].Actuated = true
			recordExistentialEffect(&decisions[i], true)
			// M-23: stamp per-action emit intent on the SUCCESSFUL-emit path (a failed actuation
			// takes the `continue` above and never reaches here, so it can't throttle its own
			// retry). This closes the cross-tick burst hole — the next tick's guard reads this
			// intent via min(observed-since, intent-since) before the observed `*-epoch` clock
			// catches up. "" (an ungoverned action) is a no-op inside Mark.
			m.Intents.Mark(pol.Tenant, decisions[i].Namespace, decisions[i].Pod,
				feasibility.ExposureVarFor(decisions[i].Action), time.Now())
			// Carry the native actuator's forensic fields into the audit (empty for Phoenix).
			decisions[i].Handler = res.Handler
			decisions[i].ObjectsTouched = res.ObjectsTouched
			decisions[i].RollbackRef = res.RollbackRef
			decisions[i].MutationKind = res.MutationKind
			actuated++
			metrics.RecordActuation(pol.Tenant, string(decisions[i].Action))
			if decisions[i].Action == model.ActionRotate {
				if !m.trackRotationWithFloor(pol.Tenant, v, tickViewByKey, pol.MinAvailableReplicas, actuationStarted) {
					m.recordActionOutcome(pol.Tenant, v, decisions[i].Action, pol.MinAvailableReplicas, actuationStarted, time.Now(), slo.OutcomeEmitted)
				}
			} else {
				outcome := slo.OutcomeEmitted
				if selectionBound(decisions[i].Action).Status == slo.StatusZero {
					outcome = slo.OutcomeCompleted
				}
				m.recordActionOutcome(pol.Tenant, v, decisions[i].Action, pol.MinAvailableReplicas, actuationStarted, time.Now(), outcome)
			}
		} else {
			stampDispatch(model.DispatchEmittedFalse, res.Note)
			m.recordActionOutcome(pol.Tenant, v, decisions[i].Action, pol.MinAvailableReplicas, actuationStarted, time.Now(), slo.OutcomeNotEmitted)
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
		Tenant:                       e.tenant,
		Namespace:                    e.namespace,
		PolicyName:                   e.key.Name,
		PolicyUID:                    e.uid,
		Mode:                         s.EffectiveMode(),
		DryRun:                       s.IsDryRun(),
		Lambda:                       s.EffectiveLambda(),
		NormSparsity:                 s.EffectiveNormSparsity(),
		FlowDisruption:               s.EffectiveFlowDisruption(),
		CostCeiling:                  s.EffectiveCostCeiling(),
		WeightSecrets:                s.EffectiveWeightSecrets(),
		BlastRadiusFromGraph:         s.AssetValue.BlastRadiusFromGraph,
		MaxMovesPerTick:              s.EffectiveMaxMovesPerTick(),
		TickInterval:                 s.EffectiveTickInterval(),
		AntiOverRotationWindow:       s.EffectiveAntiOverRotationWindow(),
		ProactiveFloor:               s.EffectiveProactiveFloor(),
		EventAgeHorizon:              s.EffectiveProactiveFloor(), // T1-B: τ_ev initialised = floor (inherited)
		ExposurePressureScale:        s.EffectiveProactiveFloor(), // T1-B: T_exp initialised = floor (inherited)
		MinAvailableReplicas:         s.EffectiveMinAvailableReplicas(),
		P99Ms:                        s.SLO.P99Ms,
		MinTokensPerSec:              s.SLO.MinTokensPerSec,
		EventDriven:                  s.Triggers.EventDriven,
		ReactiveOnly:                 s.Triggers.ReactiveOnly,
		MayBreachSLO:                 s.Existential.MayBreachSLO,
		KillChainSojournScaleSeconds: s.EffectiveSojournScaleSeconds(),
		KillChainShape:               s.EffectiveKillChainShape(),
		ExposurePressureCap:          s.EffectiveExposurePressureCap(),
		EnabledActions:               enabled,
		AssetWeightFromLabels:        s.AssetWeightFromLabels,
	}
}

func deterministicTraceID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

// metav1LabelSelector compiles the policy's selector.
func metav1LabelSelector(p *v1alpha1.PhorvexPolicy) (labels.Selector, error) {
	return metav1SelAsSel(&p.Spec.Selector)
}

// sourceOutage is the transition state of one telemetry source.
type sourceOutage struct {
	Down   bool
	Since  time.Time
	Reason string
}

// observeSourceHealth classifies this tick's scrape result: counts every failed signal query
// by reason, detects a whole-source outage from the source's OWN health verdict (a separate
// check, not an inference from "all signals errored"), logs ERROR exactly once when the source
// goes down and once when it recovers, and keeps the outage state for updateStatus to publish
// as the TelemetryDegraded condition. What absence means for phase or cost is T1-C's table.
func (m *Manager) observeSourceHealth(e *policyEntry, err error) {
	if m.MetricsSource == nil {
		return
	}
	source := m.MetricsSource.Name()
	health := ingest.SourceHealth{Source: source}
	if hr, ok := m.MetricsSource.(ingest.HealthReporter); ok {
		health = hr.LastHealth()
	} else if err != nil {
		health = ingest.SourceHealth{Source: source, Total: 1, Failed: 1}
	}
	now := time.Now()
	m.mu.Lock()
	if m.degraded == nil {
		m.degraded = map[string]*sourceOutage{}
	}
	st := m.degraded[source]
	if st == nil {
		st = &sourceOutage{}
		m.degraded[source] = st
	}
	wasDown, since := st.Down, st.Since
	if health.Unreachable() {
		if !wasDown {
			st.Down, st.Since, st.Reason = true, now, model.ReasonSourceUnreachable
		}
	} else if wasDown {
		st.Down, st.Since, st.Reason = false, time.Time{}, ""
	}
	m.mu.Unlock()

	switch {
	case health.Unreachable():
		metrics.RecordScrapeFailure(source, "*", model.ReasonSourceUnreachable)
		if !wasDown {
			m.Log.Error(err, "telemetry source unreachable: every signal query failed; affected signals read State=Error, no value fabricated",
				"source", source, "namespace", e.namespace, "failedQueries", health.Failed, "totalQueries", health.Total)
		}
	case err != nil:
		for _, sig := range failedSignals(err) {
			metrics.RecordScrapeFailure(source, sig, model.ReasonQueryFailed)
		}
		m.Log.V(1).Info("telemetry scrape partially degraded (per-signal State=Error with reason)",
			"source", source, "namespace", e.namespace, "failedQueries", health.Failed, "totalQueries", health.Total)
		if wasDown {
			m.Log.Info("telemetry source recovered", "source", source, "namespace", e.namespace, "downFor", now.Sub(since).String())
		}
	default:
		if wasDown {
			m.Log.Info("telemetry source recovered", "source", source, "namespace", e.namespace, "downFor", now.Sub(since).String())
		}
	}
}

// failedSignals extracts the signal names from PodMetrics' joined error ("sig: err" lines).
func failedSignals(err error) []string {
	var out []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if i := strings.Index(line, ":"); i > 0 {
			out = append(out, strings.TrimSpace(line[:i]))
		}
	}
	return out
}

// sourceOutageState returns a copy of the configured source's outage state.
func (m *Manager) sourceOutageState() (string, sourceOutage) {
	if m.MetricsSource == nil {
		return "", sourceOutage{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if st := m.degraded[m.MetricsSource.Name()]; st != nil {
		return m.MetricsSource.Name(), *st
	}
	return m.MetricsSource.Name(), sourceOutage{}
}

// observeEventTrust reports the SecurityEvent stream's trust verdicts (PHORVEXSEC-193 / M-94).
// Untrusted events are already excluded from belief at ingest and counted in
// phorvex_security_events_total; this makes the stream legible to an operator without one log
// line per tick: ERROR once when untrusted events appear, one Info line when they clear.
func (m *Manager) observeEventTrust(events []model.SecurityEventInfo) {
	untrusted := 0
	samples := make([]string, 0, 3)
	unresolved := 0
	for _, e := range events {
		unresolved += len(e.UnresolvedTargets)
		if e.Trust == ingest.TrustTrusted {
			continue
		}
		untrusted++
		if len(samples) < 3 {
			identity := e.CreatorIdentity
			if identity == "" {
				identity = "<unstamped>"
			}
			samples = append(samples, e.Name+" source="+e.Source+" creator="+identity+" verdict="+e.Trust)
		}
	}
	m.mu.Lock()
	was := m.untrustedEvents
	m.untrustedEvents = untrusted
	m.mu.Unlock()

	switch {
	case untrusted > 0 && was == 0:
		m.Log.Error(nil, "SecurityEvents from unallowlisted or unstamped creators are present; they carry NO belief evidence (M-94)",
			"untrusted", untrusted, "trustedDetectors", ingest.EventTrust().List(), "samples", samples, "unresolvedTargets", unresolved)
	case untrusted == 0 && was > 0:
		m.Log.Info("SecurityEvent stream is fully attributed again: every event carries an allowlisted creator", "previouslyUntrusted", was)
	}
}
