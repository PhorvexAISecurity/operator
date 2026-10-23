/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package runner is the per-tenant orchestration: it holds the live set of
// PhorvexPolicies (the tenant registry), and a single tick Runnable that, at the next
// policy or maintenance deadline, builds ONE cluster ingest snapshot and processes every DUE tenant
// (ingest -> graph -> exposure -> decide -> audit/metrics -> [active] actuate). One
// snapshot shared across tenants keeps a tick cheap (NFR1). Per-tenant cadence is
// honored by scheduling from the shared-snapshot admission time. Ticks remain serialized:
// work and outages can delay service, and snapshot failures retry at a bounded maintenance wake.
package runner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/calib"
	"github.com/phorvex/phorvex/internal/capability"
	sharedcapacity "github.com/phorvex/phorvex/internal/capacity"
	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
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
	// owner keys the learned state (M-140); tenant remains the DISPLAY name so ledger
	// entries and metrics keep their existing identity and comparability.
	owner string
	// epoch is the owner generation this rotation was EMITTED under. Feedback arriving
	// after a replacement must not be credited to the new identity (M-140 R1.2).
	epoch  uint64
	tenant string
	// ledgerID is the historical entry identity, built from the display tenant so the
	// slo.Ledger keeps byte-identical IDs across this change.
	ledgerID string
	// ledgerRecorded reports whether an outcome has already been written for this
	// rotation. It decides which arm of the removal rule applies: with no entry we may
	// write one honest unmeasured close; with an entry we must not touch it, because
	// Ledger.Record REPLACES on an ID match and would erase a measured floor.
	ledgerRecorded       bool
	startedAt            time.Time
	referenceAtStart     time.Duration
	censorDeadline       time.Time
	view                 model.WorkloadView
	knownUIDs            map[string]struct{}
	minAvailableReplicas int
	selectionBound       slo.Bound
	costObserved         bool
	// Phoenix fields bind asynchronous execution feedback to this exact submit.
	// Empty EventUID denotes the native direct-eviction path.
	decisionID       string
	phoenixEventName string
	phoenixEventUID  string
	phoenixTargetUID string
	phoenix          bool
	receiptConfirmed bool
	censorObserved   bool
}

// Manager owns the tenant registry and the tick loop.
// codeExecVerifier is the M-6 admission oracle the runner consumes: the O(1) cached gate
// check (Available, via capability.AdmissionVerifier) plus the pre-submit FinalCheck (a
// fresh, deadline-bounded re-verify + unexpired + epoch + scope) used immediately before an
// irreversible ephemeral-container injection. *codeexec.Verifier satisfies it.
type codeExecVerifier interface {
	capability.AdmissionVerifier
	FinalCheck(ctx context.Context, namespace string) (ok bool, reason string)
}

// codeExecAwareEligibility is the production capability closure the CoverageEngine invokes
// per (asset, action). PRECEDENCE is the M-6 regression invariant: the full T1-E gate
// (capWit.Eligible — which includes the code-exec admission leg) is consulted FIRST, and the
// M99 no-rbac fallback applies ONLY when Eligible returns nil (eligible). So a code-exec move
// whose admission is unverified is excluded by the code-exec leg and can NEVER be re-admitted
// by the qualified-outcome/SLO path. Extracted from the tick closure so the precedence is
// unit-tested against the exact code the runtime runs.
func codeExecAwareEligibility(
	capWit capability.Witness,
	authzNil bool,
	hasQualified func(*model.WorkloadView) bool,
	v *model.WorkloadView, a model.Action, coverKeys []string,
) *model.Eligibility {
	if v != nil && v.Pod.OptOut.Engaged {
		return &model.Eligibility{Excluded: true, Kind: model.ExclusionOperatorOptOut, Detail: "operator Pod opt-out: " + v.Pod.OptOut.Cause}
	}
	return eligibilityFrom(capWit.Eligible(v, a, coverKeys), authzNil, hasQualified, v)
}

// codeExecAwareEligibilityObserved is the READ-ONLY counterpart the counterfactual arm gets
// (M-163). It runs the SAME gate with the SAME precedence — the M99 no-rbac fallback still
// applies only when the full gate returns eligible — but its RBAC leg answers from
// authorization already reviewed instead of issuing a SelfSubjectAccessReview. A shadow can
// therefore neither spend apiserver budget nor cache an authorization answer that the next
// REAL gate would then read instead of re-reviewing.
func codeExecAwareEligibilityObserved(
	capWit capability.Witness,
	authzNil bool,
	hasQualified func(*model.WorkloadView) bool,
	v *model.WorkloadView, a model.Action, coverKeys []string,
) *model.Eligibility {
	if v != nil && v.Pod.OptOut.Engaged {
		return &model.Eligibility{Excluded: true, Kind: model.ExclusionOperatorOptOut, Detail: "operator Pod opt-out: " + v.Pod.OptOut.Cause}
	}
	return eligibilityFrom(capWit.EligibleObserved(v, a, coverKeys), authzNil, hasQualified, v)
}

// capabilityGate builds BOTH T1-E collaborators from one per-tick witness (M-163). They are
// built together, in one place, because the brain's contract is that a reviewing gate without
// its observation-only twin makes the counterfactual comparison unavailable: wiring only the
// first would silently disable the shadow arm, and wiring only the second would disable
// production's real RBAC check. Extracted from the tick so the pairing is unit-tested against
// the exact code the runtime runs.
func capabilityGate(
	capWit capability.Witness,
	authzNil bool,
	hasQualified func(*model.WorkloadView) bool,
) brainapi.Gate {
	return brainapi.Gate{
		Capability: func(v *model.WorkloadView, a model.Action, coverKeys []string) *model.Eligibility {
			return codeExecAwareEligibility(capWit, authzNil, hasQualified, v, a, coverKeys)
		},
		ShadowCapability: func(v *model.WorkloadView, a model.Action, coverKeys []string) *model.Eligibility {
			return codeExecAwareEligibilityObserved(capWit, authzNil, hasQualified, v, a, coverKeys)
		},
	}
}

// eligibilityFrom adapts one capability.Reason and applies the M99 fallback. Shared by both
// modes so the precedence invariant cannot drift between them.
func eligibilityFrom(
	r *capability.Reason,
	authzNil bool,
	hasQualified func(*model.WorkloadView) bool,
	v *model.WorkloadView,
) *model.Eligibility {
	if r == nil {
		if authzNil && hasQualified(v) {
			return &model.Eligibility{Excluded: true, Kind: capability.ReasonNoRBAC, Detail: "m99: RBAC checker unavailable"}
		}
		return nil
	}
	return &model.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
}

type Manager struct {
	// VocabularyReader reads only the named PhorvexPolicy CRD, bypassing the
	// informer cache so schema upgrades are observable without a restart.
	VocabularyReader client.Reader
	vocabulary       atomic.Pointer[ActionVocabulary]
	OwnershipReader  client.Reader // uncached, read-only owner evidence
	// BoundaryReader bypasses informer staleness for admission enforcement and
	// actuation-brake authority reads.
	BoundaryReader client.Reader
	// OperatorNamespace locates exact-UID protected output-policy journal slots.
	// Production wires it independently of the chosen actuator backend so a
	// pending output operation fences any later same-Pod move.
	OperatorNamespace string
	// EndpointLeaseAuthorityEnabled means the reviewed source, proxy image and
	// engine image pins were configured at startup. A missing journal reader or
	// namespace then fences every selected move on the same vLLM Pod.
	EndpointLeaseAuthorityEnabled bool
	// LossHistory is the bounded immutable completed-disclosure ledger. Nil
	// leaves representation history honestly unavailable.
	LossHistory losshistory.Ledger
	// CurrentInventory is bounded, expiring evidence for explicitly configured
	// synthetic protected versions. Nil keeps current inventory unavailable.
	CurrentInventory currentinventory.Ledger
	// ScopedOutcomeProducer is an optional reporting-only synthetic session
	// observer. Its operation hook and Drain are nonblocking; unavailable or full
	// reporting never delays or suppresses defensive dispatch.
	ScopedOutcomeProducer interface {
		model.PersistenceObservationAuthority
		RecordNativeRotate(model.Policy, *model.WorkloadView, actuatorapi.Request, actuatorapi.Result, time.Time) bool
		Drain(int) []model.ScopedOutcomeDelivery
	}
	// LossHistoryReader performs optional completed-disclosure authority and
	// replacement-owner reads under a separate bounded context. Production sets
	// it to the uncached API reader; a stall cannot consume the actuation tick.
	LossHistoryReader client.Reader
	// LossHistoryReadTimeout bounds the whole optional representation-evidence
	// transaction, including current-inventory revalidation. Zero uses the
	// conservative default in completed_disclosure.go.
	LossHistoryReadTimeout time.Duration
	lossHistoryWorkerMu    sync.Mutex
	lossHistoryWorker      *lossHistoryCoordinator
	// ActuationBrakeReadTimeout bounds each uncached Namespace/Pod authority read.
	// Zero uses actuationbrake.DefaultReadTimeout.
	ActuationBrakeReadTimeout time.Duration
	Client                    client.Client
	Clock                     *exposure.Clock
	Intents                   *exposure.Intents // M-23: per-action emit intent (cross-tick burst guard)
	Failures                  actionFailures    // M-19: owner/Pod-UID/action failure feedback
	FailureNow                func() time.Time  // exact clock seam for cooldown tests
	fallbackDecisions         []model.Decision  // tick-local distinct audit attempts
	Audit                     *audit.Logger
	// Sensor observes the cluster and its telemetry. Nil runs Local's sensor over this
	// manager's readers and PromURL.
	Sensor sensorapi.Sensor
	// ActuatorService acts on the cluster. Nil runs Local's actuator over
	// BoundaryReader, OperatorNamespace and Authz.
	ActuatorService actuatorapi.Actuator
	// PromURL feeds the GPU-half physics witness (DCGM via Prometheus) on the live tick; empty =
	// K8s-only signals (GPU half stays honest-absent/neutral).
	PromURL string
	// SharedCapacity is the durable cross-policy CAS ledger for hard resources
	// whose effects can outlive a tick or this process.
	SharedCapacity *sharedcapacity.Store
	// Authz is the T1-E SSAR capability checker (cached) of this process's identity, which
	// the in-process actuator acts as. nil disables the RBAC leg of the gate (installability
	// + cover + runtime-capability still apply); the boot layer wires it from the cluster
	// clientset so no-rbac exclusions become live. A remote actuator (ActuatorService)
	// reviews its own identity instead.
	Authz *authz.Checker
	// CodeExec is the M-6 code-exec admission-capability verifier. nil disables the code-exec
	// leg (debugger/custom-inject then fall through the other gates); the boot layer wires a
	// real verifier + starts its periodic re-verify, so at runtime an unverified admission
	// policy fail-closes those two actions out of both the offer set (gate: Available) and the
	// dispatch path (pre-submit: FinalCheck).
	CodeExec     codeExecVerifier
	KillSwitch   *KillSwitch
	BaseInterval time.Duration
	// PerTickTimeout bounds one tick so a slow/hung API server cannot wedge the loop
	// goroutine indefinitely (P4b livelock fix). 0 => defaulted in Start.
	PerTickTimeout time.Duration
	Log            logr.Logger
	// Calibration runs the PHVX-74 scale fit in shadow. Its values are exported and
	// monitored but never read by production scoring.
	Calibration *calib.Runtime

	Recorder          record.EventRecorder
	ActuationRecorder record.EventRecorder
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
	// Brain is the decision service. Nil serves Local's brain.
	Brain brainapi.Brain
	// Local are the services this process runs itself, for each of Brain, Sensor and
	// ActuatorService that is nil.
	Local      LocalServices
	BrainImage string
	GitSHA     string

	mu sync.RWMutex
	// emits is the per-policy ledger of ENACTED-move timestamps that feeds the rolling
	// Status.Actuated / Status.MovesThisWindow (PHORVEXSEC-176). It lives on the Manager,
	// not the policyEntry, so a spec edit (Upsert) does not forget real actuations. It is
	// in-memory only: a restart or leadership change can only UNDER-report until the next
	// emit — never claim an actuation the running brain did not perform.
	emits map[string]*emissionHistory
	// degraded tracks each telemetry source's outage state so a whole-source failure is
	// logged ONCE on transition (down / recovered), surfaced as a policy condition and
	// counted — never one ERROR line per tick (PHORVEXSEC-200 / M-113, P-LOUD-OUTAGE).
	degraded map[string]*sourceOutage
	// telemetrySource names the source of the last telemetry read.
	telemetrySource string
	policies        map[string]*policyEntry
	// untrustedEvents is the last tick's count of SecurityEvents that supplied no belief
	// evidence because their creator was not an allowlisted detector (M-94). It exists so the
	// stream is reported ONCE per transition instead of every tick.
	untrustedEvents int
	// Accessed only by the single tick loop. The RLS outcome is capped after its
	// [0,2] observation window, but ledger-enabled censored entries remain here so
	// their disruption floor keeps increasing until recovery is actually observed.
	pendingRotations map[string]pendingRotation
	// [M-140] lifecycle is the queue of ownership events enqueued by the controller
	// goroutine (Remove, and Upsert that replaces one identity with another) and drained
	// by the tick loop. Nothing is pruned at enqueue: removal COMPLETES at the drain,
	// which is the only point that owns the engine exclusively. Per-owner arrival order
	// is preserved by appending to a single slice.
	lifecycle []lifecycleEvent
	// epochs is the liveness/generation table. A deferred producer carries the epoch it
	// was issued under; a write whose owner is absent or whose epoch is stale is dropped
	// without allocating. Guarded by mu, like the queue.
	epochs map[string]uint64
	// [M-140 R1.4] publishedTenants remembers every display name whose ownership signals
	// were published. publishOwnership iterates only CURRENT names, so without this a name
	// whose last owner was removed would keep serving its final sample forever.
	publishedTenants map[string]struct{}
	// [M-140 R1.2] tickEpochs is the owner->epoch picture captured WITH this tick's due set.
	// A deferred producer validates against it, so feedback issued under one identity can
	// never be credited to the replacement that took its place mid-tick. Written and read
	// only by the tick goroutine.
	tickEpochs map[string]uint64
	// epochsTracked records that this manager has registered at least one generation, i.e.
	// that Upsert is in use. Directly-constructed managers (offline paths and focused tests)
	// never register one and must not have their feedback dropped; once tracking is on it
	// applies to every owner, so a retired owner can never masquerade as unregistered.
	epochsTracked bool
	// scheduleClock is a private seam for exact scheduler tests. Production leaves it nil
	// and uses monotonic time.Timer deadlines.
	scheduleClock managerClock
}

type killSwitchTickState struct {
	observation KillSwitchObservation
}

func legacyKillSwitchObservation(engaged bool) KillSwitchObservation {
	if engaged {
		return KillSwitchObservation{Engaged: true, Cause: KillSwitchStaticFlag}
	}
	return KillSwitchObservation{Cause: KillSwitchStaticOnly}
}

func (s *killSwitchTickState) retain(observation KillSwitchObservation) KillSwitchObservation {
	if s.observation.Engaged {
		return s.observation
	}
	s.observation = observation
	return s.observation
}

func (s *killSwitchTickState) observe(ctx context.Context, killSwitch *KillSwitch) KillSwitchObservation {
	if s.observation.Engaged {
		return s.observation
	}
	return s.retain(killSwitch.Observe(ctx))
}

func clearDispatchResult(d *model.Decision) {
	d.Actuated = false
	d.Handler = ""
	d.ObjectsTouched = nil
	d.RollbackRef = ""
	d.MutationKind = ""
	d.GracefulTermination = nil
	d.Phoenix = nil
	d.DispatchOutcome, d.DispatchReason = "", ""
}

func cloneGracefulTermination(in *model.GracefulTerminationReceipt) *model.GracefulTerminationReceipt {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

// resetDispatchAttempt removes every result and runtime-boundary field from a
// prior call while restoring a valid pre-attempt trace state. Decisions may be
// reused by tests and by audit plumbing; no later early return may serialize a
// previous emission, brake or kill-switch observation as current evidence.
func resetDispatchAttempt(d *model.Decision) {
	clearDispatchResult(d)
	d.DryRun = false
	d.DryRunCause = ""
	d.ActuationBrakeCause = ""
	d.KillSwitch = false
	d.KillSwitchCause = ""
	if d.Measurements != nil {
		d.Measurements.KillSwitch = model.OptionalBool{Present: true, Value: false}
	}
	if d.Existential != nil && d.Existential.Present {
		d.Existential.EffectStatus = "not-attempted"
	}
	reason := "pending-dispatch"
	if !d.Selected {
		reason = "unselected"
	}
	if d.Trace != nil {
		d.Trace.DryRun = false
		d.Trace.DryRunCause = ""
		d.Trace.ActuationBrakeCause = ""
		d.Trace.KillSwitchEngaged = false
		d.Trace.KillSwitchCause = ""
		if d.Trace.Existential != nil && d.Trace.Existential != d.Existential && d.Trace.Existential.Present {
			d.Trace.Existential.EffectStatus = "not-attempted"
		}
	}
	stampDispatchEvidence(d, model.DispatchNotAttempted, reason)
}

func stampKillSwitchRefusal(d *model.Decision, observation KillSwitchObservation) {
	clearDispatchResult(d)
	d.KillSwitch = true
	d.KillSwitchCause = string(observation.Cause)
	if d.Measurements != nil {
		d.Measurements.KillSwitch = model.OptionalBool{Present: true, Value: true}
	}
	if d.Trace != nil {
		d.Trace.KillSwitchEngaged = true
		d.Trace.KillSwitchCause = string(observation.Cause)
	}
	if d.Selected {
		stampDispatchEvidence(d, model.DispatchNotAttempted, "kill-switch")
	}
}

type tickResult uint8

const (
	tickNoSnapshot tickResult = iota
	tickSnapshotSucceeded
	tickSnapshotFailed
	tickInterrupted
)

// duePolicy freezes one policy's scheduling identity for the lifetime of a tick.
// entry retains the admitted configuration even if Upsert replaces the live pointer;
// cadence writes target the current same-UID entry.
type duePolicy struct {
	entry                *policyEntry
	dueAt                time.Time
	neverRun             bool
	namespace, name, uid string
	owner                string
	epoch                uint64
}

func sortDuePolicies(due []duePolicy) {
	sort.Slice(due, func(i, j int) bool {
		left, right := due[i], due[j]
		if left.neverRun != right.neverRun {
			return left.neverRun
		}
		if !left.neverRun && !left.dueAt.Equal(right.dueAt) {
			return left.dueAt.Before(right.dueAt)
		}
		if left.namespace != right.namespace {
			return left.namespace < right.namespace
		}
		if left.name != right.name {
			return left.name < right.name
		}
		return left.uid < right.uid
	})
}

type managerTimer interface {
	C() <-chan time.Time
	Reset(time.Duration)
	Stop()
}

type managerClock interface {
	Now() time.Time
	NewTimer(time.Duration) managerTimer
}

type wallManagerClock struct{}

func (wallManagerClock) Now() time.Time { return time.Now() }
func (wallManagerClock) NewTimer(d time.Duration) managerTimer {
	return &wallManagerTimer{timer: time.NewTimer(d)}
}

type wallManagerTimer struct{ timer *time.Timer }

func (t *wallManagerTimer) C() <-chan time.Time   { return t.timer.C }
func (t *wallManagerTimer) Reset(d time.Duration) { t.timer.Reset(d) }
func (t *wallManagerTimer) Stop()                 { t.timer.Stop() }

func (m *Manager) managerClock() managerClock {
	if m.scheduleClock != nil {
		return m.scheduleClock
	}
	return wallManagerClock{}
}

// lifecycleEvent is one ownership transition awaiting the tick-loop drain. It carries the
// departing owner's full METRIC identity, not just its key: a coalesced replacement never
// calls Remove, so without this the predecessor's series would be exported forever (R2.2).
type lifecycleEvent struct {
	owner     string
	tenant    string
	namespace string
	policy    string
	uid       string
	// replacedBy is set when an Upsert changed identity, so the drain can report the
	// actual completion cause rather than inferring a NotFound reconcile that never ran.
	replacedBy string
	// metricsOnly marks a display-name change under an UNCHANGED identity: retire the stale
	// label set, but keep every learned store and the creation record.
	metricsOnly bool
	// newTenant is the display name replacing `tenant` on a metricsOnly event.
	newTenant string
}

// New constructs a Manager whose in-process services are local (internal/inprocess,
// composed by cmd). Brain, Sensor and ActuatorService, set, replace them with the
// remote services.
func New(c client.Client, log logr.Logger, local LocalServices) *Manager {
	identity := buildinfo.Current()
	return &Manager{
		Client:          c,
		OwnershipReader: c,
		Clock:           exposure.NewClock(),
		Intents:         exposure.NewIntents(),
		Audit:           audit.New(log, nil),
		Local:           local,
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

// Upsert adds or updates a tenant policy in the registry.
func (m *Manager) Upsert(p *v1alpha1.PhorvexPolicy) error {
	if _, _, _, err := p.Spec.EffectiveCostPreferences(); err != nil {
		return err
	}
	if _, _, err := p.Spec.EffectiveDisruptionAversion(); err != nil {
		return fmt.Errorf("policy %s/%s: %w", p.Namespace, p.Name, err)
	}
	sel, err := metav1LabelSelector(p)
	if err != nil {
		return err
	}
	// [M-140] Production identity is the policy UID. Without it the owner key would fall
	// back to the display name and silently reacquire the shared-bucket semantics this fix
	// removes, so a malformed object is rejected rather than quietly downgraded.
	if p.UID == "" {
		return fmt.Errorf("policy %s/%s has no UID; refusing to register an unidentified owner", p.Namespace, p.Name)
	}
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	m.mu.Lock()
	defer m.mu.Unlock()
	// [M-140 R1.3] A UID identifies exactly one economic unit. If another policy already
	// owns this UID, accepting it would alias two histories and let one removal destroy the
	// other's state. Reject before touching the registry so the existing policy is unharmed.
	for otherKey, other := range m.policies {
		if other != nil && other.uid == string(p.UID) && otherKey != key.String() {
			return fmt.Errorf("policy %s already owns UID %s; refusing to alias %s onto the same owner",
				otherKey, p.UID, key.String())
		}
	}
	existing := m.policies[key.String()]
	last := time.Time{}
	unsupportedTicks := 0
	unsupportedSignature := ""
	if existing != nil && existing.uid == string(p.UID) {
		last = existing.lastTick
		if existing.generation == p.Generation {
			unsupportedTicks = existing.actionsUnsupportedTicks
			unsupportedSignature = existing.actionsUnsupportedSignature
		}
	}
	if existing != nil && existing.uid != string(p.UID) {
		delete(m.emits, key.String())
	}
	entry := &policyEntry{
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
	// [M-140] A delete immediately followed by a recreate can collapse into ONE reconcile
	// whose Get already sees the new object, so Remove never runs. Detect the identity
	// change here and enqueue the predecessor's cleanup; otherwise its learned state would
	// be inherited by the new policy and its stores would leak forever.
	if existing != nil && existing.uid == entry.uid && existing.tenant != entry.tenant {
		// Same identity, new display name (R2.2): the old label set must stop being
		// exported, but learned state and creation metadata belong to the unchanged owner
		// and are deliberately left alone.
		m.enqueueLifecycleLocked(lifecycleEvent{
			owner: existing.ownerKey(), tenant: existing.tenant, namespace: existing.namespace,
			policy: existing.key.Name, uid: existing.uid,
			metricsOnly: true, newTenant: entry.tenant,
		})
	}
	if existing != nil && existing.uid != entry.uid {
		m.enqueueLifecycleLocked(lifecycleEvent{
			owner: existing.ownerKey(), tenant: existing.tenant, namespace: existing.namespace,
			policy: existing.key.Name, uid: existing.uid, replacedBy: entry.uid,
		})
	}
	m.policies[key.String()] = entry
	// A same-UID PATCH must NOT bump the epoch: identity is unchanged, so learning continues
	// and the configured seed is not reconsumed.
	if m.epochs == nil {
		m.epochs = map[string]uint64{}
	}
	m.epochsTracked = true
	if _, known := m.epochs[entry.ownerKey()]; !known {
		m.epochs[entry.ownerKey()] = 1
	}
	return nil
}

// ownerKey is the disjoint identity that owns this entry's learned state.
func (e *policyEntry) ownerKey() string {
	return model.OwnerKey(model.OwnerKindUID, e.uid)
}

// enqueueLifecycleLocked appends an ownership event and, for events that actually change
// ownership, invalidates the owner's epoch. Callers hold m.mu. Nothing is pruned here:
// removal completes at the tick-loop drain.
func (m *Manager) enqueueLifecycleLocked(ev lifecycleEvent) {
	m.lifecycle = append(m.lifecycle, ev)
	if ev.metricsOnly {
		// [M-140 R3.1] A display-name change under an unchanged UID retires stale LABELS
		// only. The economic identity is untouched, so bumping the generation here would
		// invalidate that owner's in-flight rotation feedback and silently stop its
		// learning — exactly the reset-on-PATCH behaviour this fix must not introduce.
		return
	}
	// Bump rather than delete so a late producer carrying the old epoch is recognisably
	// stale; the entry is dropped by the drain once cleanup completes, bounding the table.
	if m.epochs == nil {
		m.epochs = map[string]uint64{}
	}
	m.epochs[ev.owner] = m.epochs[ev.owner] + 1
}

// Remove drops a tenant policy and ENQUEUES its learned-state cleanup. The prune itself
// happens at the tick-loop drain (M-140): pruning here would mutate the decision engine
// from the controller goroutine, which m.mu does not protect, and would race the tick.
func (m *Manager) Remove(key types.NamespacedName) {
	m.mu.Lock()
	e := m.policies[key.String()]
	delete(m.policies, key.String())
	delete(m.emits, key.String())
	if e != nil {
		m.enqueueLifecycleLocked(lifecycleEvent{
			owner: e.ownerKey(), tenant: e.tenant, namespace: e.namespace,
			policy: e.key.Name, uid: e.uid,
		})
	}
	m.mu.Unlock()
	if e != nil {
		// Series retirement happens at the drain, with the same identity every other
		// lifecycle path uses, so Remove and coalesced replacement behave identically.
		metrics.ResetKillSwitchStatus(e.key.Namespace, e.key.Name)
	}
}

// capturedEpoch returns the generation this TICK was admitted under, so a rotation emitted
// during the tick is stamped with the identity that was actually decided for. Reading the
// live epoch here instead would stamp a replacement's generation onto its predecessor's
// rotation whenever an Upsert landed mid-tick. Falls back to the live value for producers
// that run outside a tick (offline paths and focused tests).
func (m *Manager) capturedEpoch(owner string) uint64 {
	if epoch, ok := m.tickEpochs[owner]; ok {
		return epoch
	}
	return m.ownerEpoch(owner)
}

// ownerEpoch reads an owner's current generation.
func (m *Manager) ownerEpoch(owner string) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.epochs[owner]
}

// ownerCurrent reports whether an owner is still live AT the generation a producer was
// issued under. This is the guard that makes the epoch bookkeeping load-bearing rather
// than decorative: a write whose epoch has moved on is stale and must be dropped.
//
// The distinction is per-MANAGER, not per-owner: a manager that has never registered a
// generation (offline paths, directly-constructed test managers) has nothing to invalidate
// and accepts everything. Once Upsert has registered even one owner, generations apply to
// all of them, so a retired owner whose entry was dropped at the drain can never be
// mistaken for one that was simply never registered.
func (m *Manager) ownerCurrent(owner string, epoch uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.epochsTracked {
		return true // generations are not in use at all on this manager
	}
	current, known := m.epochs[owner]
	return known && current == epoch
}

// ownersOf counts the live policies sharing one display tenant name.
func (m *Manager) ownersOf(tenant string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, e := range m.policies {
		if e != nil && e.tenant == tenant {
			n++
		}
	}
	return n
}

// uniqueOwnerOf reports whether this display name maps to exactly one economic unit, which
// is the only case in which the legacy per-tenant lambda series can be truthful.
func (m *Manager) uniqueOwnerOf(tenant string) bool { return m.ownersOf(tenant) == 1 }

// publishOwnership republishes the collision gauge for every live display name and withdraws
// the legacy per-tenant series wherever a name has stopped being unique.
func (m *Manager) publishOwnership() {
	m.mu.Lock()
	counts := map[string]int{}
	for _, e := range m.policies {
		if e != nil {
			counts[e.tenant]++
		}
	}
	if m.publishedTenants == nil {
		m.publishedTenants = map[string]struct{}{}
	}
	// Names that were published before but have no live owner now must be cleared, not
	// left at their last value. Bounded: an entry is dropped once it has been cleared.
	retired := make([]string, 0)
	for tenant := range m.publishedTenants {
		if _, live := counts[tenant]; !live {
			retired = append(retired, tenant)
			delete(m.publishedTenants, tenant)
		}
	}
	for tenant := range counts {
		m.publishedTenants[tenant] = struct{}{}
	}
	// Identify each name that is now owned by exactly one policy, so its legacy series can
	// be restored from that survivor's own retained sample.
	unique := map[string]*policyEntry{}
	for _, e := range m.policies {
		if e != nil && counts[e.tenant] == 1 {
			unique[e.tenant] = e
		}
	}
	m.mu.Unlock()
	for _, tenant := range retired {
		metrics.ClearTenantOwnership(tenant)
	}
	for tenant, n := range counts {
		metrics.SetTenantOwnerCount(tenant, n)
	}
	// [M-140 R2.1] SetTenantOwnerCount only withdraws; it cannot restore. A name that has
	// returned to a single owner republishes that owner's LAST OBSERVED lambda, so the
	// series does not stay absent until the next decision. If the survivor has produced no
	// sample the series stays absent — a value is never invented, and no learned state is
	// allocated to produce one.
	for tenant, e := range unique {
		metrics.RestoreUniqueOwnerSample(tenant, e.namespace, e.key.Name, e.uid)
	}
}

// syncOwnerLiveness tells the decision engine which owners still exist. A deferred producer
// (late rotation feedback, a stale tick) that reaches the engine for an absent owner is then
// dropped instead of lazily recreating that owner's bucket at the DEFAULT seed.
func (m *Manager) syncOwnerLiveness() {
	m.mu.RLock()
	epochs := make([]model.PolicyEpoch, 0, len(m.policies))
	for _, e := range m.policies {
		if e != nil {
			epochs = append(epochs, model.PolicyEpoch{Namespace: e.namespace, Name: e.key.Name, UID: e.uid, Generation: e.generation})
		}
	}
	m.mu.RUnlock()
	m.brain().RegisterOwnerEpochs(epochs)
}

func (m *Manager) drainScopedOutcomes(limit int) []model.ScopedOutcomeDelivery {
	if m.ScopedOutcomeProducer == nil || limit <= 0 {
		return nil
	}
	return m.ScopedOutcomeProducer.Drain(limit)
}

// registerCoverageOwnerEpochs is shared by the controller sync seam and the
// actual tick snapshot. A future observed-outcome adapter therefore cannot see
// a different policy identity depending on which manager path established it.
func (m *Manager) brain() brainapi.Brain {
	if m.Brain != nil || m.Local == nil {
		return m.Brain
	}
	return m.Local.Brain()
}

// actuation returns the actuator the tick acts through, nil when none is wired:
// ActuatorService when set, else Local's actuator over this manager's boundary
// reader, operator namespace and access checker.
func (m *Manager) actuation() actuatorapi.Actuator {
	if m.ActuatorService != nil || m.Local == nil {
		return m.ActuatorService
	}
	return m.Local.Actuation(m.BoundaryReader, m.OperatorNamespace, m.Authz)
}

// Actuation returns the actuator the manager acts through: the remote service
// when one is set, else the in-process backend; nil when neither is wired.
func (m *Manager) Actuation() actuatorapi.Actuator { return m.actuation() }

// routeBackend is the backend whose routes a dispatch needs prepared. Without an
// actuator nothing dispatches, and the hybrid routes are the conservative answer.
func (m *Manager) routeBackend() actuatorapi.Backend {
	if act := m.actuation(); act != nil {
		return act.Backend()
	}
	return actuatorapi.BackendHybrid
}

// access is the authorization the capability gate reviews: the acting identity's,
// answered by the actuator. It is nil when the actuator reviews none.
func (m *Manager) access() capability.Access {
	if act := m.actuation(); act != nil && act.ReviewsAccess() {
		return act
	}
	return nil
}

// quarantineCapacity reports the namespace's retained-quarantine capacity.
func (m *Manager) quarantineCapacity(ctx context.Context, namespace string) actuatorapi.QuarantineCapacity {
	if act := m.actuation(); act != nil {
		return act.QuarantineCapacity(ctx, namespace)
	}
	return actuatorapi.QuarantineCapacity{}
}

// sensor returns the sensor the tick observes the cluster through.
func (m *Manager) sensor() sensorapi.Sensor {
	if m.Sensor != nil || m.Local == nil {
		return m.Sensor
	}
	return m.Local.Sensor(m.Client, m.OwnershipReader, m.BoundaryReader, m.PromURL)
}

// selectorString is a policy selector in the form sensorapi.Scope carries; nil
// selects every Pod.
func selectorString(sel labels.Selector) string {
	if sel == nil {
		return ""
	}
	return sel.String()
}

// observedContext is a Pod's graph and event context. The sensor builds it for
// every Pod a due policy selects; a Pod it lacks has no neighbours and no events.
func observedContext(obs *sensorapi.Observation, p *model.Pod) sensorapi.PodContext {
	if c, ok := obs.Context[p.Namespace+"/"+p.Name]; ok {
		return c
	}
	return sensorapi.PodContext{Neighbors: []model.NeighborRef{}, Events: []model.SecurityEventInfo{}, InfectionFrontier: 1}
}

// DrainLifecycle completes every enqueued ownership transition. It runs at the top of each
// tick, INCLUDING ticks with no due policy, so a removal is never stranded behind an idle
// tenant. This is the point at which removal is complete; the audit records that point,
// not the enqueue. Exported so the controller-level lifecycle tests can drive the same
// entrypoint the tick loop uses rather than a test-only substitute.
func (m *Manager) DrainLifecycle() {
	m.mu.Lock()
	events := m.lifecycle
	m.lifecycle = nil
	m.mu.Unlock()
	if len(events) == 0 {
		return
	}
	for _, ev := range events {
		// [M-140 R2.2] Retire the departing identity's series at drain completion. This is
		// the ONLY cleanup path a coalesced replacement passes through, since it never calls
		// Remove. It deletes exactly this owner's labels, so a replacement or an unrelated
		// co-resident owner is untouched.
		if ev.uid != "" {
			metrics.ResetOwner(ev.tenant, ev.namespace, ev.policy, ev.uid)
		}
		if ev.metricsOnly {
			// [M-140 R5.1] A display-name change under an unchanged identity: labels
			// retired, learned state and creation metadata preserved. This is label
			// maintenance, NOT retirement, so it must not be recorded as an ownership
			// removal — TenantLifecycle with an empty replacedBy means "removed".
			if m.Audit != nil {
				m.Audit.TenantDisplayNameChanged(ev.tenant, ev.newTenant, ev.owner)
			}
			continue
		}
		stores := 0
		if act := m.actuation(); act != nil && ev.uid != "" {
			retained, err := act.RetirePolicyBinding(context.Background(), ev.uid)
			if err != nil {
				m.Log.Error(err, "actuator policy binding retirement failed", "policyUID", ev.uid)
			}
			if retained {
				stores++
			}
		}
		stores += m.brain().ForgetOwner(ev.owner)
		if m.Clock != nil {
			m.Clock.RetainOwner(ev.owner, nil)
			stores++
		}
		if m.Intents != nil {
			m.Intents.RetainOwner(ev.owner, nil)
			stores++
		}
		m.Failures.forgetOwner(ev.owner)
		stores++
		stores += m.closePendingForOwner(ev)
		// The owner is gone and its cleanup is complete, so the epoch entry can go too:
		// churn cannot accumulate tombstones. A later same-UID Upsert starts at 1 again.
		m.mu.Lock()
		delete(m.epochs, ev.owner)
		m.mu.Unlock()
		if m.Audit != nil {
			m.Audit.TenantLifecycle(ev.tenant, ev.owner, ev.replacedBy, stores)
		}
	}
}

// closePendingForOwner terminates in-flight rotation observations for a removed owner and
// returns how many pending entries were dropped.
//
// Two arms, because slo.Ledger.Record REPLACES an entry on an ID match: writing an
// unmeasured close under an existing ID would erase a measured or right-censored floor,
// and writing it under a NEW id would double-count the same event.
func (m *Manager) closePendingForOwner(ev lifecycleEvent) int {
	dropped := 0
	for key, p := range m.pendingRotations {
		if p.owner != ev.owner {
			continue
		}
		if !p.ledgerRecorded && m.Disruption != nil {
			// Arm 1: nothing was ever recorded for this rotation. One honest entry:
			// it was emitted and its outcome was never observed. Not right_censored,
			// which would assert a floor we never measured.
			m.Disruption.Record(slo.Entry{
				ID: p.ledgerID, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
				Action: model.ActionRotate, Cause: slo.CausePhorvex,
				StartedAt: p.startedAt, Outcome: slo.OutcomeEmitted,
				ReplicaImpact: slo.ImpactUnmeasured,
			})
		}
		// Arm 2 is the absence of an else: an already-recorded entry keeps its identity,
		// amounts, censoring, availability and observation times exactly as observed.
		if m.Audit != nil {
			m.Audit.RotationObservationTerminated(p.tenant, ev.owner, p.view.Pod.Namespace, p.view.Pod.Name, p.ledgerRecorded)
		}
		if p.phoenix {
			m.recordRotationObservation(p, "unconfirmed-owner-terminated", p.receiptConfirmed, false, time.Now())
		}
		delete(m.pendingRotations, key)
		dropped++
	}
	return dropped
}

// NeedLeaderElection explicitly documents the mutating tick loop's leader group.
// controller-runtime v0.21.0 also puts ordinary runnables in this group by default.
// Election must still be enabled on the enclosing manager.
func (*Manager) NeedLeaderElection() bool { return true }

// Start implements manager.Runnable: it runs the tick loop until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) error {
	// The in-process services' startup invariants, before the sub-second tick path.
	if m.Local != nil {
		if err := m.Local.Validate(); err != nil {
			return err
		}
	}
	releaseCircuitMetrics := metrics.BindActuationCircuitSource(m.currentActuationCircuits)
	defer releaseCircuitMetrics()
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
	clock := m.managerClock()
	baseDeadline := clock.Now().Add(m.BaseInterval)
	t := clock.NewTimer(m.BaseInterval)
	defer t.Stop()
	m.Log.Info("phorvex tick loop started", "baseInterval", m.BaseInterval.String(), "perTickTimeout", m.PerTickTimeout.String())
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C():
			// Cancellation can race a ready timer. It wins before admission, including after
			// a prior blocked tick returns because its parent context was cancelled.
			if ctx.Err() != nil {
				return nil
			}
			now := clock.Now()
			baseDeadline = nextMaintenanceDeadline(baseDeadline, now, m.BaseInterval)
			// [P4b livelock fix] bound each tick: a slow/hung API server makes the tick ctx
			// expire, CollectSnapshot/Get return promptly, the tick SKIPS (and a timed-out
			// kill-switch read fail-CLOSES per FIX 1) — the loop never wedges.
			tctx, cancel := context.WithTimeout(ctx, m.PerTickTimeout)
			result := m.tick(tctx)
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			now = clock.Now()
			// Work can cross the maintenance deadline selected before admission. Coalesce
			// again so a failed snapshot always retries in the future, never at Reset(0).
			baseDeadline = nextMaintenanceDeadline(baseDeadline, now, m.BaseInterval)
			includePolicyDeadlines := result != tickSnapshotFailed && result != tickInterrupted
			deadline := m.nextWakeDeadline(now, baseDeadline, includePolicyDeadlines)
			t.Reset(max(deadline.Sub(now), time.Duration(0)))
		}
	}
}

// currentActuationCircuits projects the existing bounded failure store at scrape time.
// Failure and ownership locks are never held together: this first takes an owned failure
// snapshot, then joins it to currently admitted policy display names. Unknown/retired
// owners are omitted rather than guessed from their encoded owner key.
func (m *Manager) currentActuationCircuits(now time.Time) []metrics.ActuationCircuit {
	open := m.Failures.openByOwner(now)
	m.mu.RLock()
	tenantByOwner := make(map[string]string, len(m.policies))
	for _, entry := range m.policies {
		if entry != nil {
			tenantByOwner[entry.ownerKey()] = entry.tenant
		}
	}
	m.mu.RUnlock()
	type labelKey struct{ tenant, action string }
	aggregated := make(map[labelKey]int)
	for key, count := range open {
		tenant := tenantByOwner[key.owner]
		if tenant == "" {
			continue
		}
		aggregated[labelKey{tenant: tenant, action: string(key.action)}] += count
	}
	rows := make([]metrics.ActuationCircuit, 0, len(aggregated))
	for key, count := range aggregated {
		rows = append(rows, metrics.ActuationCircuit{Tenant: key.tenant, Action: key.action, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Tenant != rows[j].Tenant {
			return rows[i].Tenant < rows[j].Tenant
		}
		return rows[i].Action < rows[j].Action
	})
	return rows
}

// nextMaintenanceDeadline advances a missed maintenance deadline to the first future
// period. It never replays a backlog after slow serialized work.
func nextMaintenanceDeadline(deadline, now time.Time, interval time.Duration) time.Time {
	if deadline.After(now) {
		return deadline
	}
	missed := now.Sub(deadline)/interval + 1
	return deadline.Add(missed * interval)
}

// nextWakeDeadline chooses an exact monotonic policy deadline when one is established.
// Empty histories wait for maintenance. After snapshot failure, policy deadlines are
// suppressed for one arm so unchanged history cannot create a zero-delay retry loop.
func (m *Manager) nextWakeDeadline(now, baseDeadline time.Time, includePolicies bool) time.Time {
	next := baseDeadline
	if !includePolicies {
		return next
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.policies {
		if e == nil || e.lastTick.IsZero() {
			continue
		}
		deadline := e.lastTick.Add(e.spec.EffectiveTickInterval())
		if deadline.Before(next) {
			next = deadline
		}
	}
	return next
}

// reconcileWedged converges crash-wedged actuator state (a double-leader warm-swap; an
// orphaned quarantine NetworkPolicy) for each managed namespace, idempotently. Runs every
// tick INDEPENDENT of tenant cadence (a wedged double-leader must converge even if no policy
// is "due" this tick).
func (m *Manager) reconcileWedged(ctx context.Context, initial KillSwitchObservation) KillSwitchObservation {
	if initial.Engaged {
		return initial
	}
	observation := m.KillSwitch.Observe(ctx)
	if observation.Engaged {
		m.Log.Info("kill-switch refused automatic operation maintenance",
			"killSwitchEngaged", true, "killSwitchCause", string(observation.Cause))
		return observation
	}
	act := m.actuation()
	if act == nil {
		return observation
	}
	events, supported, err := act.RecoverOperations(ctx, false)
	if !supported {
		return observation
	}
	if err != nil {
		m.Log.Error(err, "operation journal maintenance failed")
		metrics.RecordMaintenanceAttempt("journal", "refused")
		if m.Audit != nil {
			m.Audit.Maintenance("", "", "", "", "", "", "", "", "journal-read-failed", "", err)
		}
		return observation
	}
	for _, ev := range events {
		metrics.RecordMaintenanceAttempt(ev.Kind, ev.Outcome)
		if ev.Err != nil {
			m.Log.Error(ev.Err, "operation maintenance incomplete", "receipt", ev.Receipt, "policyUID", ev.PolicyUID, "targetUID", ev.TargetUID, "outcome", ev.Outcome, "effect", ev.Effect)
		}
		if m.Audit != nil {
			m.Audit.Maintenance(ev.Receipt, ev.Kind, ev.Tenant, ev.PolicyNamespace, ev.PolicyName, ev.PolicyUID, ev.TargetName, ev.TargetUID, ev.Outcome, ev.Effect, ev.Err)
		}
	}
	return observation
}

// tick builds one cluster snapshot and processes all due tenants.
func (m *Manager) tick(ctx context.Context) (result tickResult) {
	started := time.Now()
	defer func() {
		outcome := metrics.ManagerTickFinished
		switch result {
		case tickNoSnapshot:
			outcome = metrics.ManagerTickNoSnapshot
		case tickSnapshotFailed:
			outcome = metrics.ManagerTickSnapshotFailed
		case tickInterrupted:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				outcome = metrics.ManagerTickDeadline
			} else {
				outcome = metrics.ManagerTickCanceled
			}
		}
		metrics.RecordManagerTick(outcome, time.Since(started))
	}()
	if ctx.Err() != nil {
		return tickInterrupted
	}
	// One bounded CRD read at most per refresh period, before any tenant witness.
	// The published observation remains fixed for this serialized tick.
	m.refreshVocabulary(ctx, m.managerClock().Now())
	if ctx.Err() != nil {
		return tickInterrupted
	}
	// [M-140] Complete pending ownership transitions BEFORE any snapshot or decision work,
	// on every tick including ones with no due policy, so a removal is never stranded behind
	// an idle tenant and no decision is priced from a departed owner's state.
	m.DrainLifecycle()
	m.publishOwnership()
	// [M-140 R1.2] Liveness and the due-policy snapshot are taken under ONE hold of m.mu.
	// Doing them separately let a controller Upsert land in between, putting a brand-new UID
	// into `due` while the engine had not yet been told it was live — the decision would
	// then be rejected as retired. They must describe the same instant.
	m.mu.Lock()
	due := make([]duePolicy, 0, len(m.policies))
	liveEpochs := make([]model.PolicyEpoch, 0, len(m.policies))
	dueEpochs := make(map[string]uint64, len(m.policies))
	now := m.managerClock().Now()
	for _, e := range m.policies {
		owner := e.ownerKey()
		liveEpochs = append(liveEpochs, model.PolicyEpoch{Namespace: e.namespace, Name: e.key.Name, UID: e.uid, Generation: e.generation})
		row := duePolicy{
			entry: e, namespace: e.namespace, name: e.key.Name, uid: e.uid,
			owner: owner, epoch: m.epochs[owner], neverRun: e.lastTick.IsZero(),
		}
		if !row.neverRun {
			row.dueAt = e.lastTick.Add(e.spec.EffectiveTickInterval())
		}
		if row.neverRun || !row.dueAt.After(now) {
			due = append(due, row)
			dueEpochs[owner] = row.epoch
		}
	}
	m.mu.Unlock()
	sortDuePolicies(due)
	if brain := m.brain(); brain.PersistenceObservations() {
		brain.RegisterOwnerEpochs(liveEpochs)
		if m.ScopedOutcomeProducer != nil {
			brain.SetPersistenceAuthority(m.ScopedOutcomeProducer)
		}
		for _, delivery := range m.drainScopedOutcomes(32) {
			if delivery.Observation != nil {
				brain.AdmitPersistenceObservation(*delivery.Observation)
			} else {
				brain.RecordScopedOutcomeUnavailable(delivery.Policy, delivery.Reason)
			}
		}
	}
	// The epochs captured with `due` travel with this tick: a producer that writes back
	// later compares against them, so a replacement that happened mid-tick cannot be
	// credited with the departed identity's feedback.
	m.tickEpochs = dueEpochs
	m.PublishTenantCollisions(ctx)

	m.refreshEmissionStatus(ctx, now)
	killObservation := m.KillSwitch.Observe(ctx)
	metrics.SetKillSwitch(killObservation.Engaged)

	// [PHVX-2] Online cost calibration has its own off-switch, evaluated every tick from the same
	// sentinel ConfigMap so it takes effect without a restart. `ok=false` means the sentinel could
	// not be read; hold the current state rather than discard every tenant's calibration on a
	// transient API error.
	if frozen, ok := m.KillSwitch.CalibrationFrozen(ctx); ok {
		m.brain().SetCostCalibrationFrozen(frozen)
	}

	// [PHVX-10c] Publish calibrator state after applying the switch, including explicit zeroes when
	// a tenant's pending queue drains. Without the zero update, the gauge remains stuck at its last
	// nonzero value forever.
	m.publishRLSMetrics()

	// [P4b] converge crash-WEDGED actuator state (double-leader warm-swap; orphaned quarantine
	// NetworkPolicy) EVERY tick, independent of tenant cadence — unless the kill-switch is
	// engaged (a deliberate global freeze) or actuation is unavailable.
	if !killObservation.Engaged && m.actuation() != nil {
		killObservation = m.reconcileWedged(ctx, killObservation)
		metrics.SetKillSwitch(killObservation.Engaged)
	}
	if ctx.Err() != nil {
		return tickInterrupted
	}

	calibrationDue := m.Calibration != nil && m.Calibration.Due(now)
	if len(due) == 0 && !calibrationDue {
		return tickNoSnapshot
	}

	scopes := make([]sensorapi.Scope, 0, len(due))
	for _, row := range due {
		scopes = append(scopes, sensorapi.Scope{Namespace: row.entry.namespace, Selector: selectorString(row.entry.selector)})
	}
	// The sensor reads owner evidence only for the due policies' Pods, and only when
	// native rotation consumes it.
	obs, err := m.sensor().Observe(ctx, sensorapi.ObserveRequest{Now: now, Scopes: scopes, ResolveOwners: actuatorUsesNativeRotate(m.actuation())})
	if err != nil {
		m.Log.Error(err, "ingest snapshot failed; skipping tick")
		if ctx.Err() != nil {
			return tickInterrupted
		}
		return tickSnapshotFailed
	}
	if ctx.Err() != nil {
		return tickInterrupted
	}

	m.observeEventTrust(obs.Events)

	// Complete post-action feedback before making this tick's decisions. This is
	// non-blocking: recovery is measured from the Kubernetes snapshots the runner
	// already collects, never by waiting inside Actuate.
	m.observeReadyRotations(obs)

	// The sensor derives the full-cluster witness once. It is shared by every tenant and
	// by the shadow calibrator; repeated derivation would make refresh cost grow with
	// tenant count.
	if calibrationDue {
		if _, _, err := m.Calibration.ObserveFleet(calib.Fleet{Now: obs.Now, Pods: obs.Pods, Nodes: obs.Nodes}, obs.Physics); err != nil {
			m.Log.Error(err, "shadow calibration export failed; metrics and in-memory result remain available")
		}
	}
	if ctx.Err() != nil {
		return tickInterrupted
	}

	for _, row := range due {
		if ctx.Err() != nil {
			return tickInterrupted
		}
		if !m.ownerCurrent(row.owner, row.epoch) {
			continue
		}
		m.processTenantObserved(ctx, obs, row.entry, &killObservation)
		metrics.SetKillSwitch(killObservation.Engaged)
		if ctx.Err() != nil {
			return tickInterrupted
		}
	}
	return tickSnapshotSucceeded
}

func (m *Manager) publishRLSMetrics() {
	pendingByTenant := map[string]int{}
	for _, p := range m.pendingRotations {
		pendingByTenant[p.tenant]++
	}

	for tenant, st := range m.brain().CalibrationState() {
		metrics.SetRLSState(tenant, st.Primed, st.Updates)
		metrics.SetRotationsPending(tenant, pendingByTenant[tenant])
		delete(pendingByTenant, tenant)
	}
	// A pending rotation can be registered before its tenant bucket is visible. Publish those too;
	// they will move through the calibrated-state loop on subsequent ticks.
	for tenant, n := range pendingByTenant {
		metrics.SetRotationsPending(tenant, n)
	}
}

// rotationObservationKey keys a pending rotation by its OWNER (M-140) so two policies
// sharing a display name track their own feedback independently and a removal prunes only
// its own entries. The ledger keeps a tenant-built identity; see pendingRotation.ledgerID.
func rotationObservationKey(owner string, view *model.WorkloadView) string {
	return owner + "\x00" + view.Pod.Namespace + "\x00" + view.Pod.UID
}

// rotationLedgerID preserves the pre-M-140 entry identity, built from the DISPLAY tenant,
// so historical disruption evidence keeps byte-identical IDs and stays comparable.
func rotationLedgerID(tenant string, view *model.WorkloadView) string {
	return tenant + "\x00" + view.Pod.Namespace + "\x00" + view.Pod.UID
}

// trackRotation records only controller-owned rotations for optimizers that can
// consume feedback. Without a controller identity there is no honest way to match
// a replacement, so the observation remains unavailable rather than fabricated.
func (m *Manager) trackRotation(owner, tenant string, view *model.WorkloadView, allViews map[string]*model.WorkloadView, startedAt time.Time) bool {
	return m.trackRotationWithFloor(owner, tenant, view, allViews, -1, startedAt)
}

// trackRotationWithFloor freezes the service's availability threshold at action
// start so the disruption ledger can record breach-seconds separately from
// replica-seconds. A negative floor means the threshold was unavailable.
func (m *Manager) trackRotationWithFloor(owner, tenant string, view *model.WorkloadView, allViews map[string]*model.WorkloadView, minAvailableReplicas int, startedAt time.Time) bool {
	return m.trackRotationReceipt(owner, tenant, view, allViews, minAvailableReplicas, startedAt, actuatorapi.Result{}, "")
}

func (m *Manager) trackRotationReceipt(owner, tenant string, view *model.WorkloadView, allViews map[string]*model.WorkloadView, minAvailableReplicas int, startedAt time.Time, result actuatorapi.Result, decisionID string) bool {
	costObserver := m.brain().LearnsRotationCost()
	if (result.Actuator != "phoenix" && !costObserver && m.Calibration == nil && m.Disruption == nil) || view == nil {
		return false
	}
	if view.Pod.OwnerKind == "" || view.Pod.OwnerName == "" || view.Pod.UID == "" {
		if m.Calibration != nil {
			m.Calibration.ObserveRotation(calib.RotationRecord{
				ID:     fmt.Sprintf("%s/%s/%s@%d", tenant, view.Pod.Namespace, view.Pod.Name, startedAt.UnixNano()),
				Tenant: tenant, Namespace: view.Pod.Namespace, Pod: view.Pod.Name, Action: string(model.ActionRotate),
				StartedAt: startedAt, RecordedAt: startedAt, Outcome: calib.OutcomeInvalid,
				InvalidReason:    "controller owner or pod UID unavailable; replacement cannot be matched",
				ReferenceAtStart: model.ReadyDelayReference,
				CensorDeadline:   startedAt.Add(2 * model.ReadyDelayReference),
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
	key := rotationObservationKey(owner, view)
	if _, alreadyPending := m.pendingRotations[key]; alreadyPending {
		return true // repeated Phoenix emits must not reset the original recovery clock
	}
	m.pendingRotations[key] = pendingRotation{
		owner: owner, epoch: m.capturedEpoch(owner), tenant: tenant,
		ledgerID: rotationLedgerID(tenant, view), startedAt: startedAt,
		referenceAtStart:     model.ReadyDelayReference,
		censorDeadline:       startedAt.Add(2 * model.ReadyDelayReference),
		view:                 *view,
		knownUIDs:            known,
		minAvailableReplicas: minAvailableReplicas,
		selectionBound:       selectionBound(model.ActionRotate),
		decisionID:           decisionID,
	}
	if result.Actuator == "phoenix" {
		p := m.pendingRotations[key]
		p.phoenix = true
		p.phoenixEventName = result.EventName
		p.phoenixEventUID = result.EventUID
		p.phoenixTargetUID = view.Pod.UID
		m.pendingRotations[key] = p
	}
	return true
}

func phoenixRotationReceiptConfirmed(p pendingRotation, snap *sensorapi.Observation) bool {
	if p.phoenixEventName == "" || p.phoenixEventUID == "" || p.phoenixTargetUID == "" || snap == nil || !snap.PhoenixReceiptInventoryComplete {
		return false
	}
	r, ok := snap.PhoenixReceipts[p.phoenixEventName]
	if !ok || r.EventName != p.phoenixEventName || r.EventUID != p.phoenixEventUID || r.RuleType != amtdv1beta1.PhorvexRuleTypeRotate ||
		r.ThreatLevel != amtdv1beta1.PhorvexRuleThreatLevel || r.RuleSource != amtdv1beta1.PhorvexRuleSource || len(r.Targets) != 1 ||
		r.Targets[0] != p.view.Pod.Namespace+"/"+p.view.Pod.Name ||
		r.TargetUID != p.phoenixTargetUID || r.AppliedAction != "rotate" ||
		r.CreatedAt.IsZero() || r.ProcessedAt.IsZero() {
		return false
	}
	// Kubernetes metav1.Time is serialized at whole-second precision. Compare all
	// lifecycle boundaries at that precision so a genuine same-second receipt is
	// accepted while pre-dispatch, post-deadline, and future timestamps are not.
	created := r.CreatedAt.Truncate(time.Second)
	processed := r.ProcessedAt.Truncate(time.Second)
	started := p.startedAt.Truncate(time.Second)
	deadline := p.censorDeadline.Truncate(time.Second)
	if created.Before(started) || processed.Before(created) || processed.Before(started) || processed.After(deadline) {
		return false
	}
	if !snap.Now.IsZero() && (created.After(snap.Now.Truncate(time.Second)) || processed.After(snap.Now.Truncate(time.Second))) {
		return false
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
func (m *Manager) observeReadyRotations(snap *sensorapi.Observation) {
	brain := m.brain()
	costObserver := brain.LearnsRotationCost()
	if snap == nil || len(m.pendingRotations) == 0 {
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
		phoenix := p.phoenix
		if phoenix && !p.receiptConfirmed && phoenixRotationReceiptConfirmed(p, snap) {
			p.receiptConfirmed = true
			m.pendingRotations[ref.key] = p
			m.recordRotationObservation(p, "confirmed-execution-recovery-pending", true, false, snap.Now)
		}
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
						ID: p.ledgerID, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
						Action: string(model.ActionRotate), StartedAt: p.startedAt, RecordedAt: snap.Now,
						Elapsed: elapsed, Outcome: calib.OutcomeInvalid,
						InvalidReason:    "original pod UID remained present through the observation deadline",
						ReferenceAtStart: p.referenceAtStart, CensorDeadline: p.censorDeadline,
					})
				}
				if phoenix {
					if !p.ledgerRecorded && m.Disruption != nil {
						m.recordUnknownRotation(p, snap.Now)
					}
					outcome := "unconfirmed-execution"
					if p.receiptConfirmed {
						outcome = "confirmed-execution-recovery-censored"
					}
					m.recordRotationObservation(p, outcome, p.receiptConfirmed, false, snap.Now)
				}
				m.Log.Info("rotation cost observation unavailable; original UID still present",
					"tenant", p.tenant,
					"pod", p.view.Pod.Namespace+"/"+p.view.Pod.Name,
					"oldUID", p.view.Pod.UID)
			}
			continue
		}
		// Pod disappearance alone is not Phoenix execution feedback. An unrelated
		// rollout can remove this UID and create a same-owner Ready Pod while the
		// exact SecurityEvent remains unprocessed or was recreated. Retain the
		// unknown until the bounded deadline; never train or measure disruption from
		// that replacement without the exact terminal receipt.
		if phoenix && !p.receiptConfirmed {
			if snap.Now.Before(p.censorDeadline) {
				continue
			}
			if !p.ledgerRecorded && m.Disruption != nil {
				m.recordUnknownRotation(p, snap.Now)
			}
			m.recordRotationObservation(p, "unconfirmed-execution", false, false, snap.Now)
			if costObserver {
				metrics.ObserveRotationOutcome(p.tenant, metrics.RLSAbandoned)
			}
			if m.Calibration != nil {
				m.Calibration.ObserveRotation(calib.RotationRecord{
					ID: p.ledgerID, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
					Action: string(model.ActionRotate), StartedAt: p.startedAt, RecordedAt: snap.Now,
					Elapsed: elapsed, Outcome: calib.OutcomeInvalid,
					InvalidReason:    "original Pod disappeared without the exact Phoenix execution receipt",
					ReferenceAtStart: p.referenceAtStart, CensorDeadline: p.censorDeadline,
				})
			}
			delete(m.pendingRotations, ref.key)
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
				// [M-140 R1.2] Drop feedback whose owner is gone or has been replaced since
				// the rotation was emitted, rather than training the successor on it.
				if m.ownerCurrent(p.owner, p.epoch) {
					brain.ObserveRotation(p.owner, &p.view, measuredFlow)
				}
			}
			if m.Calibration != nil {
				calibrationOutcome := calib.OutcomeObserved
				if calibrationCensored {
					calibrationOutcome = calib.OutcomeCensored
				}
				record := calib.RotationRecord{
					ID: p.ledgerID, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
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
				ID:                           p.ledgerID,
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
			// [M-140] From here on this rotation HAS ledger evidence. If its owner is removed
			// later, the close must not re-Record: Ledger.Record replaces on ID match and would
			// overwrite these measured amounts with an unmeasured entry.
			p.ledgerRecorded = true
			m.pendingRotations[ref.key] = p
		}
		if ledgerCensored {
			if phoenix && !p.censorObserved {
				m.recordRotationObservation(p, "confirmed-execution-recovery-censored", true, false, observationEnd)
				p.censorObserved = true
				m.pendingRotations[ref.key] = p
			}
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
		if phoenix {
			m.recordRotationObservation(p, "confirmed-execution-recovery", true, replacement != nil, observationEnd)
		}
	}
}

func (m *Manager) recordUnknownRotation(p pendingRotation, observedAt time.Time) {
	m.Disruption.Record(slo.Entry{
		ID: p.ledgerID, Tenant: p.tenant, Namespace: p.view.Pod.Namespace, Pod: p.view.Pod.Name,
		Action: model.ActionRotate, Cause: slo.CausePhorvex, StartedAt: p.startedAt,
		ObservedAt: observedAt, Outcome: slo.OutcomeEmitted, ReplicaImpact: slo.ImpactUnmeasured,
		SelectionBoundStatus:   p.selectionBound.Status,
		SelectionBoundEvidence: selectionBoundEvidence(p.selectionBound),
	})
}

func (m *Manager) recordRotationObservation(p pendingRotation, outcome string, executionConfirmed, recoveryConfirmed bool, observedAt time.Time) {
	metrics.RecordActuationConfirmation("phoenix", outcome)
	if m.Audit != nil {
		m.Audit.RotationObservation(p.tenant, p.owner, p.decisionID, p.view.Pod.Namespace, p.view.Pod.Name,
			p.view.Pod.UID, p.phoenixEventName, p.phoenixEventUID, outcome, executionConfirmed, recoveryConfirmed,
			p.startedAt, observedAt)
	}
}

// creditCadence advances only the identity admitted in this tick. An in-flight
// predecessor must never stamp its admission time onto a replacement UID.
func (m *Manager) creditCadence(ctx context.Context, e *policyEntry, admittedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	if cur := m.policies[e.key.String()]; cur != nil && cur.uid == e.uid {
		cur.lastTick = admittedAt
	}
}

// actuatorUsesNativeRotate reports whether rotate reaches the native eviction
// handler for the configured actuator. Hybrid routes rotate to native so it
// must apply the same owner-identity feasibility law as the native backend.
func actuatorUsesNativeRotate(a actuatorapi.Actuator) bool {
	if a == nil {
		return false
	}
	return actuatorapi.RouteFor(a.Backend(), model.ActionRotate) == actuatorapi.BackendNative
}

// processTenantObserved runs one policy's tick on the sensor's observation.
func (m *Manager) processTenantObserved(ctx context.Context, obs *sensorapi.Observation, e *policyEntry, killObservation *KillSwitchObservation) {
	if ctx.Err() != nil {
		return
	}
	start := time.Now()
	if killObservation == nil {
		fallback := m.KillSwitch.Observe(ctx)
		killObservation = &fallback
		if ctx.Err() != nil {
			return
		}
	}
	killState := &killSwitchTickState{observation: *killObservation}
	killEngaged := killState.observation.Engaged
	pol := buildPolicy(e)
	admittedOwnerEpoch := m.capturedEpoch(pol.Owner())
	if capacity := m.quarantineCapacity(ctx, e.namespace); capacity.Configured {
		pol.QuarantineCapacityConfigured = true
		pol.QuarantineCapacityLimit = capacity.Limit
		pol.QuarantineCapacityKnown = capacity.Known
		if capacity.Known {
			pol.QuarantineCapacityUsed = capacity.Used
		} else {
			pol.QuarantineCapacityReason = capacity.Reason
		}
		if ctx.Err() != nil {
			return
		}
	}
	if m.SharedCapacity != nil {
		pol.SharedResourceCapacityConfigured = true
		inventory, inventoryErr := m.SharedCapacity.Inventory(ctx)
		if inventoryErr != nil {
			pol.SharedResourceReservationsKnown = false
			pol.SharedResourceReservationsReason = inventoryErr.Error()
		} else {
			pol.SharedResourceReservationsKnown = true
			pol.SharedResourceReservations = inventory
		}
		if ctx.Err() != nil {
			return
		}
	}
	pol.NativeRotate = actuatorUsesNativeRotate(m.actuation())
	pol.TraceEnabled = m.DecisionTraceEnabled
	pol.BrainImage = m.BrainImage
	pol.GitSHA = m.GitSHA
	pol.TickID = deterministicTraceID("tick", obs.Now.UTC().Format(time.RFC3339Nano), pol.PolicyUID, pol.Tenant)

	// P-PHYSICS (UCW): the sensor derives one discovered witness map for the shared
	// observation. Honest-absent (NeutralPhysics) when no scan answers.
	evidenceEvents := obs.EvidenceEvents

	// Select this tenant's pods.
	var selPods []*model.Pod
	for i := range obs.Pods {
		p := &obs.Pods[i]
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
	if read := m.sensor().Telemetry(ctx, sensorapi.TelemetryRequest{Namespace: e.namespace, Pods: names}); read.Configured {
		// M-130/M-113: use the BEST-EFFORT map even on a partial scrape failure (dropping the
		// whole tick's telemetry was the silent-outage bug). A source failure is surfaced as a
		// metric + an error log, and per-signal State=Error keeps absence distinguishable.
		if read.Telemetry != nil {
			tele = read.Telemetry
		}
		m.observeSourceHealth(e, read)
		if ctx.Err() != nil {
			return
		}
	}

	pol.DecisionAssets = map[string]string{}
	for _, pod := range selPods {
		pol.DecisionAssets[pod.Namespace+"/"+pod.Name] = pod.UID
	}
	for _, ev := range evidenceEvents {
		if len(ev.Outcomes) > 0 {
			pol.TrustBoundaryReason = "uncached-boundary-reader-unavailable"
			if m.BoundaryReader != nil {
				boundaryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				pol.TrustBoundaryReady, pol.TrustBoundaryReason, pol.TrustBoundarySince = eventtrust.CheckExistentialBoundary(boundaryCtx, m.BoundaryReader)
				cancel()
			}
			break
		}
	}
	if ctx.Err() != nil {
		return
	}
	keep := make(map[string]struct{}, len(selPods))
	failureKeep := make(map[string]struct{}, len(selPods))
	views := make([]*model.WorkloadView, 0, len(selPods))
	for _, p := range selPods {
		t := tele[p.Name]
		// M-23: one fingerprint per CLOCKED exposure variable — pod identity, session,
		// plus the per-action `*-epoch` markers (absent-skipped when a marker is missing). The
		// [PHVX-67] session clock still resets when either KV flush bumps p.SessionEpoch.
		m.Clock.Observe(exposure.Observation{
			Owner:        pol.Owner(),
			Namespace:    p.Namespace,
			Pod:          p.Name,
			StartedAt:    p.StartedAt,
			Fingerprints: model.ExposureFingerprints(*p),
		}, obs.Now)
		keep[exposure.SlotKey(pol.Owner(), p.Namespace, p.Name)] = struct{}{}
		failureKeep[p.Namespace+"\x00"+p.UID] = struct{}{}
		exp := m.Clock.Since(pol.Owner(), p.Namespace, p.Name, obs.Now)
		// Per-action emit intent (M-23): the most recent EMISSION per variable, stamped at the
		// emit boundary before the observed epoch catches up. The guard takes min(exp, intent).
		intent := m.Intents.Since(pol.Owner(), p.Namespace, p.Name, obs.Now)

		podContext := observedContext(obs, p)
		ph, okPh := obs.Physics[p.Namespace+"/"+p.Name]
		if !okPh {
			ph = model.NeutralPhysics()
		}
		viewPod := *p
		viewPod.RouteServiceReady = declaredRouteServiceExists(p, obs.Services)
		phase, phaseReason := model.ClassifyPhase(*p, t)
		if pol.P99Ms > 0 && !t.P99Ms.Usable() {
			// SLO latency headroom unmeasurable: the gate is skipped (never blocks, P-NO-FREEZE)
			// and counted, instead of passing as a silent full-headroom 1.0 (B-3).
			metrics.RecordSLOGateSkipped(pol.Tenant, t.P99Ms.State.String())
		}
		views = append(views, &model.WorkloadView{
			Pod:                viewPod,
			Telemetry:          t,
			Phase:              phase,
			PhaseReason:        phaseReason,
			BlastRadius:        podContext.BlastRadius,
			NeighborCount:      podContext.NeighborCount,
			Neighbors:          podContext.Neighbors,
			Events:             podContext.Events,
			OutcomeEvents:      evidenceEvents,
			ExposureByVariable: exp,
			IntentByVariable:   intent,
			Physics:            ph,
			InfectionFrontier:  podContext.InfectionFrontier,
		})
	}
	// T1-E: build ONE per-tick capability witness (the single predicate home) and use it
	// for BOTH the ActionsSupported status (capability leg only, via Capable) AND the
	// generator's pre-scoring gate (full Eligible incl. installability + RBAC) — so the
	// two can never drift into the M-20 mirror. The access leg is absent until the actuator
	// reviews its identity's access (then no-rbac becomes live). Unknown discovery supplies no
	// invented absent actions and is published separately as unverified evidence.
	vocabulary := m.VocabularySnapshot()
	var absent model.InstallSet
	if vocabulary.Known {
		absent = vocabulary.NotInstallable
	}
	access := m.access()
	capWit := capability.BuildWitness(ctx, capability.BuildIndex(obs.Pods, obs.Nodes, obs.Services), absent, access, m.actuation()).
		WithCodeExec(m.CodeExec, obs.NamespaceLabels).
		WithOperatorNamespace(m.OperatorNamespace).
		WithPolicyIdentity(pol.PolicyName, pol.PolicyUID)
	actionsSupport := m.debounceActionsSupported(e, capabilityGaps(pol, views, capWit))
	brain := m.brain()
	gate := capabilityGate(capWit, access == nil,
		func(vv *model.WorkloadView) bool { return model.HasQualifiedOutcome(vv, pol) })
	if brain.GatesCandidates() {
		m.Failures.retain(pol.Owner(), failureKeep)
		failureNow := obs.Now
		if m.FailureNow != nil {
			failureNow = m.FailureNow()
		}
		gate.FailureExclusion = func(vv *model.WorkloadView, a model.Action) (string, bool) {
			return m.Failures.exclusion(failureKey{pol.Owner(), vv.Pod.Namespace, vv.Pod.UID, a}, failureNow)
		}
	}

	// Standing route state belongs to the policy tick, not to a selected move.
	// Observe it before selection so zero-Pod, zero-selection and rejected ticks
	// all retain the same owned configuration evidence.
	namespaceObservation := obs.NamespaceDryRun[e.namespace]
	if namespaceObservation.Cause == "" {
		namespaceObservation = actuationbrake.Namespace(nil)
	}
	brakeState := &actuationBrakeTickState{namespace: namespaceObservation}
	standingPolicy, ownerCurrent := m.maintainStandingPolicy(ctx, e, pol, admittedOwnerEpoch, killState, brakeState)
	if !ownerCurrent || ctx.Err() != nil {
		return
	}
	actionsSupport.standingPolicy = &standingPolicy
	killEngaged = killState.observation.Engaged
	namespaceObservation = brakeState.namespace

	var shadowDecisions []model.Decision
	shadowAvailable := false
	if m.Calibration != nil {
		if shadowViews, ok := m.Calibration.ShadowViews(views); ok {
			decisions, supported, shadowErr := brain.DecideShadow(brainapi.DecideRequest{Views: shadowViews, Policy: pol, Gate: gate})
			if supported {
				shadowDecisions = decisions
				shadowAvailable = shadowErr == nil
				if shadowErr != nil {
					m.Log.Error(shadowErr, "shadow scale optimizer comparison unavailable", "tenant", pol.Tenant)
				}
			}
		}
	}
	// Retain exact source and effective policy material once per content hash in
	// the production audit sibling store. Persistence failure follows the audit
	// degradation contract and never changes defensive selection or actuation;
	// Logger.Record marks every affected row unavailable/failed explicitly.
	if m.Audit != nil && brain.Name() == "p1-coverage" {
		if set, provenanceErr := brain.ParameterSet(pol); provenanceErr == nil {
			_ = m.Audit.RetainParameterSet(pol.Tenant, set.Reference, set.Manifest, set.Overrides)
		}
	}

	// Math Lab: the brain records an allowlisted policy's tick for offline replay. It copies
	// inputs before the engine runs and the raw decisions right after; the recording never
	// changes a decision and drops its own snapshot rather than delaying the tick.
	decisions, recording, err := brain.Decide(brainapi.DecideRequest{Views: views, Policy: pol, Gate: gate,
		Capture: &brainapi.Capture{Spec: e.spec, CapturedAt: obs.Now}})
	defer recording.Close()
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		reason, currentFailure := checkedSelectionRejectionReason(err)
		if !currentFailure {
			m.Log.Info("decision tick dropped after policy owner retirement", "tenant", pol.Tenant)
			return
		}
		// A replacement can be admitted while this producer is running. Status has
		// its own UID guard; keep metrics and audit on the same current-owner side
		// of that boundary instead of attributing a stale rejection to the new UID.
		if !m.ownerCurrent(pol.Owner(), admittedOwnerEpoch) {
			return
		}
		dur := time.Since(start)
		metrics.PublishRejectedTick(pol.Tenant, pol.PolicyName, len(views), dur.Seconds(), reason)
		m.Log.Error(err, "action set rejected; decisions and actuation suppressed for tick",
			"tenant", pol.Tenant, "optimizer", brain.Name(), "reason", string(reason))
		m.Audit.RejectedTickSummary(pol.Tenant, pol.Namespace, pol.PolicyName, pol.PolicyUID, len(views), dur, pol.Mode, string(reason),
			killState.observation.Engaged, string(killState.observation.Cause))
		rejected, provenanceErr := brain.RejectedDecisions(brainapi.RejectedTick{Views: views, Policy: pol, Reason: string(reason), Now: obs.Now})
		if provenanceErr != nil {
			m.Log.Error(provenanceErr, "rejected decision parameter provenance unavailable", "tenant", pol.Tenant)
			return
		}
		for _, d := range rejected {
			m.Audit.Record(d)
		}
		inventory := outcomeInventory(evidenceEvents, pol)
		if inventory != nil {
			m.Audit.RecordOutcomeInventory(pol.Tenant, obs.Now, inventory)
		}
		if len(rejected) > 0 || inventory != nil {
			m.updateExistentialStatus(ctx, e, rejected, inventory)
		}
		actionsSupport.namespaceDryRun = namespaceObservation
		m.updateRejectedStatusObserved(ctx, e, len(views), killState.observation, time.Now(), reason, actionsSupport)
		m.Clock.RetainOwner(pol.Owner(), keep)
		m.Intents.RetainOwner(pol.Owner(), keep) // M-23: GC emit intent with the exposure clock
		brain.RetainStageClock(pol.Owner(), keep)
		m.creditCadence(ctx, e, obs.Now)
		return
	}
	if shadowAvailable {
		availabilityViolations, sloViolations := shadowSafetyViolations(shadowDecisions, views, pol)
		m.Calibration.ObserveValidation(calib.SelectionComparison{
			At:               obs.Now,
			Tenant:           pol.Tenant,
			Production:       selectedDecisionKeys(decisions),
			Shadow:           selectedDecisionKeys(shadowDecisions),
			ProductionScores: decisionScores(decisions),
			ShadowScores:     decisionScores(shadowDecisions),
		}, availabilityViolations, sloViolations)
	}

	effectiveDryRun := pol.DryRun || namespaceObservation.Engaged
	for i := range decisions {
		if decisions[i].Measurements == nil {
			decisions[i].Measurements = &model.DecisionMeasurementsV1{SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "runner-gates"}
		}
		decisions[i].Measurements.KillSwitch = model.OptionalBool{Present: true, Value: killEngaged}
	}
	if effectiveDryRun {
		for i := range decisions {
			if pol.DryRun {
				stampPolicyDryRun(&decisions[i])
			} else {
				stampNamespaceDryRun(&decisions[i], namespaceObservation)
			}
		}
	}
	if killEngaged {
		for i := range decisions {
			// The kill switch is a SEPARATE gate from dry-run: it leaves DryRun false while
			// suppressing actuation. Stamping it keeps a decision-only mirror (an operator
			// run with --global-kill-switch to feed a dashboard) distinguishable from an
			// operator whose actuator is failing. Both otherwise emit the identical record.
			stampKillSwitchRefusal(&decisions[i], killState.observation)
		}
	}
	if !standingPolicy.dispatchAllowed && !effectiveDryRun && !killEngaged && standingPolicy.blockedCause != "" {
		for i := range decisions {
			if decisions[i].Selected {
				stampDispatchEvidence(&decisions[i], model.DispatchNotAttempted, "standing-policy-guard-unavailable")
			}
		}
	}
	if ctx.Err() != nil {
		return
	}

	// M100: admit the dedicated evidence stream and freeze the reporting source
	// BEFORE actuation; no later resnapshot or
	// shared map/slice can rewrite the evidence used for this claim.
	reportClaim := model.NewClaimScope(eventtrust.EventTrust().List(), true, m.BrainImage, m.GitSHA)
	representationInventory := outcomeInventory(evidenceEvents, pol)
	versions := make(map[string]string, len(views))
	for _, v := range views {
		versions[v.Pod.Namespace+"/"+v.Pod.Name] = v.Pod.UID
	}
	// No effect has been attempted yet. Stop promptly while preparing the
	// immutable reporting inputs rather than carrying an expired tick into
	// actuation. After an attempt, the audit loop below must drain completely.
	representationInputs, historyInputs, complete := m.prepareRepresentationSnapshots(ctx, decisions, pol, versions, reportClaim, representationInventory, evidenceEvents, obs.Now)
	if !complete {
		return
	}

	// Actuate FIRST (active mode) so the audit + metrics reflect what ACTUALLY fired
	// (actuate marks decisions[i].Actuated on a successful emit).
	m.fallbackDecisions = nil
	var currentPreparation *actuatorapi.RoutePreparation
	if standingPolicy.observed {
		currentPreparation = &standingPolicy.result.Preparation
	}
	if standingPolicy.dispatchAllowed && !effectiveDryRun && !killEngaged && m.actuation() != nil && hasPermittedTarget(decisions, views) {
		viewByKey := make(map[string]*model.WorkloadView, len(views))
		for _, v := range views {
			viewByKey[v.Pod.Namespace+"/"+v.Pod.Name] = v
		}
		if ctx.Err() != nil {
			return
		}
		var attempted bool
		_, currentPreparation, attempted = m.actuatePreparedMode(ctx, e, pol, decisions, viewByKey, true, killState, brakeState, currentPreparation)
		if ctx.Err() != nil && !attempted {
			return
		}
	}
	*killObservation = killState.observation
	finalKillObservation := killState.observation
	finalNamespaceObservation := brakeState.namespace

	assessmentInput := colocationInput(obs, e)
	selected, infeasible := 0, 0
	claim := model.NewClaimScope(eventtrust.EventTrust().List(), true, m.BrainImage, m.GitSHA)
	for i := range decisions {
		decisions[i].Claim = &claim
		if decisions[i].Trace != nil {
			decisions[i].Trace.PolicyActionVocabulary = vocabulary.traceEvidence()
		}
		appendRepresentation(&decisions[i], representationInputs[i])
		m.Audit.Record(decisions[i])
		m.recordColocation(assessmentInput, decisions[i], pol)
		if decisions[i].Selected {
			selected++
		}
		if decisions[i].Action == model.ActionNoop && !decisions[i].Feasible {
			infeasible++
		}
	}
	recording.Finalize(decisions)
	for i := range m.fallbackDecisions {
		m.fallbackDecisions[i].Claim = &claim
		if m.fallbackDecisions[i].Trace != nil {
			m.fallbackDecisions[i].Trace.PolicyActionVocabulary = vocabulary.traceEvidence()
		}
		fallbackKey := m.fallbackDecisions[i].Namespace + "/" + m.fallbackDecisions[i].Pod
		if historyInputs == nil {
			appendRepresentation(&m.fallbackDecisions[i], representationSnapshotV1(m.fallbackDecisions[i], pol,
				versions[fallbackKey], reportClaim, representationInventory))
		} else {
			appendRepresentation(&m.fallbackDecisions[i], representationSnapshotV1(m.fallbackDecisions[i], pol,
				versions[fallbackKey], reportClaim, representationInventory, historyInputs[fallbackKey]))
		}
		m.Audit.Record(m.fallbackDecisions[i])
		m.recordColocation(assessmentInput, m.fallbackDecisions[i], pol)
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
	metrics.PublishTick(pol.Tenant, pol.Namespace, pol.PolicyName, pol.PolicyUID, decisions, exposuresForMetrics,
		selected, dur.Seconds(), pol.Mode, m.uniqueOwnerOf(pol.Tenant))
	m.Audit.TickSummaryForPolicy(pol.Tenant, pol.Namespace, pol.PolicyName, pol.PolicyUID, len(decisions), selected, infeasible, dur, pol.Mode,
		finalKillObservation.Engaged, string(finalKillObservation.Cause))
	m.Clock.RetainOwner(pol.Owner(), keep)
	m.Intents.RetainOwner(pol.Owner(), keep) // M-23: GC emit intent with the exposure clock
	brain.RetainStageClock(pol.Owner(), keep)
	inventory := outcomeInventory(evidenceEvents, pol)
	if inventory != nil {
		m.Audit.RecordOutcomeInventory(pol.Tenant, obs.Now, inventory)
	}
	m.updateExistentialStatus(ctx, e, decisions, inventory)
	actionsSupport.preparation = currentPreparation
	actionsSupport.namespaceDryRun = finalNamespaceObservation
	m.updateStatusObserved(ctx, e, len(views), selected, 0, finalKillObservation, time.Now(), actionsSupport)

	m.creditCadence(ctx, e, obs.Now)
}

func declaredRouteServiceExists(p *model.Pod, services []model.ServiceInfo) bool {
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

// checkedSelectionRejectionReason separates a stale lifecycle refusal from a
// failure of the current policy and bounds every externally published reason.
func checkedSelectionRejectionReason(err error) (metrics.TickRejectionReason, bool) {
	if errors.Is(err, brainapi.ErrOwnerRetired) {
		return "", false
	}
	var collision model.CrossBlockCollision
	if errors.As(err, &collision) {
		return metrics.RejectCrossBlockCollision, true
	}
	var collisionPointer *model.CrossBlockCollision
	if errors.As(err, &collisionPointer) {
		return metrics.RejectCrossBlockCollision, true
	}
	return metrics.RejectDecisionContractError, true
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
	count, _ := m.actuatePrepared(ctx, e, pol, decisions, tickViewByKey)
	return count
}

func cleanNoEffectResult(r actuatorapi.Result) bool {
	return !r.Emitted && len(r.ObjectsTouched) == 0 && r.RollbackRef == "" && (r.MutationKind == "" || r.MutationKind == "none") &&
		r.AMTDName == "" && r.EventName == "" && r.EventUID == ""
}

// noEffectDisposition accepts only the closed actuator vocabulary on a result
// with no contradictory effect evidence. The legacy typed refusal remains a
// supported producer when its result is structurally clean.
func noEffectDisposition(r actuatorapi.Result, err error) actuatorapi.NoEffectDisposition {
	switch r.NoEffect {
	case actuatorapi.NoEffectRefused:
		if cleanNoEffectResult(r) && (err == nil || actuatorapi.IsNoEffectRefusal(err)) {
			return r.NoEffect
		}
		return actuatorapi.NoEffectUnknown
	case actuatorapi.NoEffectSatisfied:
		if err == nil && cleanNoEffectResult(r) {
			return r.NoEffect
		}
		return actuatorapi.NoEffectUnknown
	case actuatorapi.NoEffectReconciled:
		if err == nil && !r.Emitted && (r.MutationKind == "" || r.MutationKind == "none") &&
			r.EventName == "" && r.EventUID == "" {
			return r.NoEffect
		}
		return actuatorapi.NoEffectUnknown
	case actuatorapi.NoEffectDeclared:
		if err == nil && !r.Emitted && len(r.ObjectsTouched) == 0 && r.RollbackRef == "" &&
			r.MutationKind == "declared" && r.EventName == "" && r.EventUID == "" {
			return r.NoEffect
		}
		return actuatorapi.NoEffectUnknown
	case actuatorapi.NoEffectUnknown:
		if actuatorapi.IsNoEffectRefusal(err) && cleanNoEffectResult(r) {
			return actuatorapi.NoEffectRefused
		}
	}
	return actuatorapi.NoEffectUnknown
}

// contradictoryNoEffectResult distinguishes an absent disposition from a
// producer that supplied a closed disposition alongside incompatible result
// evidence. The latter must never fall through to emitted-success accounting
// merely because the disposition validator correctly reduced it to unknown.
func contradictoryNoEffectResult(r actuatorapi.Result, err error) bool {
	return r.NoEffect != actuatorapi.NoEffectUnknown && noEffectDisposition(r, err) == actuatorapi.NoEffectUnknown
}

func stampDispatchEvidence(d *model.Decision, outcome, reason string) {
	d.DispatchOutcome, d.DispatchReason = outcome, reason
	if d.Trace != nil {
		d.Trace.DispatchOutcome, d.Trace.DispatchReason = outcome, reason
	}
}

// cloneExistential preserves the first attempt's evidence after a fallback
// reaches recordExistentialEffect. JSON round-tripping is unsuitable here:
// ExistentialDecision's MarshalJSON redacts content for output, so cloning must
// preserve the in-memory evidence exactly and own every mutable slice.
func cloneExistential(in *model.ExistentialDecision) *model.ExistentialDecision {
	if in == nil {
		return nil
	}
	out := *in
	out.Reasons = append([]string(nil), in.Reasons...)
	out.PrioritySelections = append([]string(nil), in.PrioritySelections...)
	out.Evidence = append([]model.OutcomeEvidence(nil), in.Evidence...)
	for i := range out.Evidence {
		out.Evidence[i].Reasons = append([]string(nil), in.Evidence[i].Reasons...)
		out.Evidence[i].Outcome.RequiredKeys = append([]string(nil), in.Evidence[i].Outcome.RequiredKeys...)
	}
	out.Candidates = append([]model.ExistentialCandidate(nil), in.Candidates...)
	for i := range out.Candidates {
		out.Candidates[i].MissingKeys = append([]string(nil), in.Candidates[i].MissingKeys...)
		out.Candidates[i].Reasons = append([]string(nil), in.Candidates[i].Reasons...)
	}
	return &out
}

func fallbackDecision(original model.Decision, a model.Alternative) model.Decision {
	d := original
	if original.Economics != nil {
		economics := *original.Economics
		d.Economics = &economics
	}
	if original.Measurements != nil {
		measurements := *original.Measurements
		d.Measurements = &measurements
	}
	d.Existential = cloneExistential(original.Existential)
	if d.Existential != nil {
		d.Existential.EffectStatus = "not-attempted"
		oldKey := d.Namespace + "/" + d.Pod + "|" + string(original.Action)
		newKey := d.Namespace + "/" + d.Pod + "|" + string(a.Action)
		for i, key := range d.Existential.PrioritySelections {
			if key == oldKey {
				d.Existential.PrioritySelections[i] = newKey
			}
		}
		for i := range d.Existential.Candidates {
			c := &d.Existential.Candidates[i]
			c.SLORelaxed = c.Action == a.Action && c.SLOExcluded && c.Contains && d.Existential.MayBreachSLO
		}
	}
	d.Action, d.CoverageValue, d.CoveredWeight, d.Cost = a.Action, a.Coverage, a.Marginal, a.Cost
	d.Resources = append([]model.ResourceConsumption(nil), a.Resources...)
	costCoefficient := original.Lambda
	if original.Economics != nil {
		costCoefficient = original.Economics.EffectiveCostCoefficient
	}
	d.Net = a.Coverage - costCoefficient*a.Cost
	if a.ObjectivePenalty.Present {
		d.Net = a.Coverage - a.ObjectivePenalty.Value
	}
	d.Attribution = append([]model.AttributionTerm(nil), a.Attribution...)
	if a.CounterfactualNote != "" {
		d.CounterfactualNote = a.CounterfactualNote
	}
	d.PerDollar = 0
	if a.Cost > 0 {
		d.PerDollar = a.Coverage / a.Cost
	}
	d.ProactiveRate = 0
	if (original.Economics == nil || original.Economics.Version != model.EconomicsIndependentPreferencesV1) && d.PerDollar > costCoefficient {
		d.ProactiveRate = d.PerDollar - costCoefficient
	}
	d.CoveredFacts = len(a.CoverKeys)
	if d.Measurements != nil {
		d.Measurements.PerDollar = model.OptionalFloat{Present: a.Cost > 0, Value: d.PerDollar}
		d.Measurements.CoveredWeight = model.OptionalFloat{Present: true, Value: d.CoveredWeight}
		d.Measurements.CoveredFacts = model.OptionalInt{Present: true, Value: d.CoveredFacts}
		d.Measurements.ProactiveRate = model.OptionalFloat{Present: a.Cost > 0 && (original.Economics == nil || original.Economics.Version != model.EconomicsIndependentPreferencesV1), Value: d.ProactiveRate}
	}
	d.Reason = fmt.Sprintf("same-tick alternative after explicit no-effect refusal of %s; reserved marginal gain %.6g", original.Action, a.Gain)
	d.Actuated, d.Phoenix = false, nil
	d.DispatchOutcome, d.DispatchReason = "", ""
	d.Handler, d.RollbackRef, d.MutationKind = "", "", ""
	d.ObjectsTouched = nil
	d.GracefulTermination = nil
	if original.Trace != nil {
		tr := *original.Trace
		tr.Existential = d.Existential
		if tr.Existential == nil {
			tr.Existential = cloneExistential(original.Trace.Existential)
		}
		tr.DecisionID = fmt.Sprintf("%s-fallback-%s", original.Trace.DecisionID, a.Action)
		tr.Candidates = append([]model.DecisionCandidateV2(nil), original.Trace.Candidates...)
		tr.Facts = append([]model.DecisionFactV2(nil), original.Trace.Facts...)
		tr.ActionStatus = append([]model.DecisionActionStatusV3(nil), original.Trace.ActionStatus...)
		tr.Resources = append([]model.DecisionResourceCapacityV6(nil), original.Trace.Resources...)
		tr.SelectedAction = string(a.Action)
		tr.SelectedCandidateKey = d.Namespace + "/" + d.Pod + "|" + string(a.Action)
		tr.DispatchOutcome, tr.DispatchReason = "", ""
		tr.DualUpdate.Applied = false // this exchange makes no second learning step
		resourceDelta := map[string]int{}
		for _, demand := range original.Resources {
			resourceDelta[demand.Scope.Key()] -= demand.Units
		}
		for _, demand := range a.Resources {
			resourceDelta[demand.Scope.Key()] += demand.Units
		}
		for i := range tr.Resources {
			tr.Resources[i].Selected += resourceDelta[tr.Resources[i].Scope.Key()]
		}
		fallbackCover := make(map[string]struct{}, len(a.CoverKeys))
		for _, key := range a.CoverKeys {
			fallbackCover[key] = struct{}{}
		}
		for i := range tr.Facts {
			fact := &tr.Facts[i]
			wasEarlier := fact.CoveredRound.Present && fact.CoveredRound.Value < tr.EvaluationRound
			_, nowCovered := fallbackCover[fact.FactKey]
			if !wasEarlier {
				fact.CoveredRound = model.OptionalInt{}
				if nowCovered {
					fact.CoveredRound = tr.SelectionRound
				}
			}
			fact.CoveredBeforeDecision = wasEarlier
		}
		for i := range tr.Candidates {
			c := &tr.Candidates[i]
			c.Existential = nil
			if tr.Existential != nil {
				for j := range tr.Existential.Candidates {
					if tr.Existential.Candidates[j].Action == model.Action(c.Action) {
						c.Existential = &tr.Existential.Candidates[j]
						break
					}
				}
			}
			c.Selected = c.Action == string(a.Action)
			if c.Selected {
				c.MarginalCoverage = model.OptionalFloat{Present: true, Value: a.Marginal}
				c.NetGain = model.OptionalFloat{Present: true, Value: a.Gain}
				c.SelectionReason = "same_tick_no_effect_alternative"
				c.SelectionRound = tr.SelectionRound
			} else {
				c.SelectionRound = model.OptionalInt{}
			}
		}
		for i := range tr.ActionStatus {
			row := &tr.ActionStatus[i]
			if row.Action == string(a.Action) {
				row.Status = model.ActionStatusSelected
				row.ExclusionKind = model.ExclusionNone
				row.Reason = "same-tick no-effect alternative"
			}
			if row.Action == string(original.Action) {
				row.Status = model.ActionStatusCandidate
				row.ExclusionKind = model.ExclusionSelection
				row.Reason = "first attempt refused without effect"
			}
		}
		d.Trace = &tr
	}
	return d
}

func (m *Manager) actuatePrepared(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, tickViewByKey map[string]*model.WorkloadView) (int, *actuatorapi.RoutePreparation) {
	state := &killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}}
	brakeState := &actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)}
	return m.actuatePreparedWithKillSwitch(ctx, e, pol, decisions, tickViewByKey, state, brakeState)
}

func (m *Manager) actuatePreparedWithKillSwitch(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, tickViewByKey map[string]*model.WorkloadView, state *killSwitchTickState, brakeState *actuationBrakeTickState) (int, *actuatorapi.RoutePreparation) {
	count, preparation, _ := m.actuatePreparedWithKillSwitchObserved(ctx, e, pol, decisions, tickViewByKey, state, brakeState)
	return count, preparation
}

func (m *Manager) actuatePreparedWithKillSwitchObserved(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, tickViewByKey map[string]*model.WorkloadView, state *killSwitchTickState, brakeState *actuationBrakeTickState) (int, *actuatorapi.RoutePreparation, bool) {
	return m.actuatePreparedMode(ctx, e, pol, decisions, tickViewByKey, true, state, brakeState, nil)
}

func actuationAttemptOutcome(res actuatorapi.Result, err error, disposition actuatorapi.NoEffectDisposition, contradictory bool) metrics.ActuationAttemptOutcome {
	if errors.Is(err, context.DeadlineExceeded) {
		return metrics.AttemptDeadline
	}
	if disposition == actuatorapi.NoEffectRefused && !contradictory {
		return metrics.AttemptRefused
	}
	if err != nil {
		return metrics.AttemptError
	}
	if contradictory {
		return metrics.AttemptUnknown
	}
	if res.Emitted {
		return metrics.AttemptAccepted
	}
	switch disposition {
	case actuatorapi.NoEffectSatisfied:
		return metrics.AttemptSatisfied
	case actuatorapi.NoEffectReconciled:
		return metrics.AttemptReconciled
	case actuatorapi.NoEffectDeclared:
		return metrics.AttemptDeclared
	default:
		return metrics.AttemptUnknown
	}
}

func sharedCapacityRequest(pol model.Policy, d model.Decision, v *model.WorkloadView) sharedcapacity.Request {
	operationID := ""
	if d.Trace != nil {
		operationID = d.Trace.DecisionID
	}
	if operationID == "" {
		operationID = deterministicTraceID("shared-capacity", pol.TickID, pol.PolicyUID, d.Namespace, v.Pod.UID, string(d.Action))
	}
	return sharedcapacity.Request{
		PolicyUID: pol.PolicyUID, TargetNamespace: d.Namespace,
		TargetName: d.Pod, TargetUID: v.Pod.UID, Action: d.Action,
		OperationID: operationID, MinAvailableReplica: pol.MinAvailableReplicas,
		Resources: append([]model.ResourceConsumption(nil), d.Resources...),
	}
}

func appendDispatchReason(d *model.Decision, suffix string) {
	if d == nil || suffix == "" {
		return
	}
	if d.DispatchReason == "" {
		d.DispatchReason = suffix
	} else {
		d.DispatchReason += "; " + suffix
	}
	if d.Trace != nil {
		d.Trace.DispatchReason = d.DispatchReason
	}
}

func releaseSharedCapacityNoEffect(ctx context.Context, store *sharedcapacity.Store, reservation *sharedcapacity.Reservation) error {
	if store == nil || reservation == nil {
		return nil
	}
	releaseCtx := ctx
	cancel := func() {}
	if ctx.Err() != nil {
		// The backend is proven unsent/no-effect at each call site. Complete this
		// bounded synchronous ledger cleanup even when the action context has just
		// expired; no goroutine or detached compensation survives the caller.
		releaseCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	}
	defer cancel()
	return store.ReleaseNoEffect(releaseCtx, reservation)
}

func (m *Manager) actuatePreparedMode(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, tickViewByKey map[string]*model.WorkloadView, allowFallback bool, state *killSwitchTickState, brakeState *actuationBrakeTickState, prepared *actuatorapi.RoutePreparation) (int, *actuatorapi.RoutePreparation, bool) {
	return m.actuatePreparedModeWithCapacity(ctx, e, pol, decisions, tickViewByKey, allowFallback, state, brakeState, nil, prepared)
}

func (m *Manager) actuatePreparedModeWithCapacity(ctx context.Context, e *policyEntry, pol model.Policy, decisions []model.Decision, tickViewByKey map[string]*model.WorkloadView, allowFallback bool, state *killSwitchTickState, brakeState *actuationBrakeTickState, inheritedReservation *sharedcapacity.Reservation, prepared *actuatorapi.RoutePreparation) (int, *actuatorapi.RoutePreparation, bool) {
	attempted := false
	inheritedHandled := inheritedReservation == nil
	defer func() {
		// A fallback inherits the original reservation while it repeats all
		// current-authority guards. If it exits before atomic exchange/backend
		// invocation, the original attempt was definitely unsent and can release.
		if !inheritedHandled && m.SharedCapacity != nil {
			if err := releaseSharedCapacityNoEffect(ctx, m.SharedCapacity, inheritedReservation); err != nil {
				m.Log.Error(err, "shared capacity reservation retained after pre-dispatch fallback refusal")
			}
		}
	}()
	// Clear prior result and boundary metadata on EVERY supplied decision before ANY
	// early exit. This must precede both the EnsurePolicy guard below (which returns
	// without entering the per-decision loop at all) and the `!Selected` skip inside it.
	// Audit.Record serializes both, so only evidence from THIS call may survive.
	for i := range decisions {
		resetDispatchAttempt(&decisions[i])
	}
	if state == nil {
		state = &killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}}
	}
	if brakeState == nil {
		brakeState = &actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)}
	}
	boundaryObservation := state.observe(ctx, m.KillSwitch)
	if ctx.Err() != nil {
		return 0, nil, attempted
	}
	if boundaryObservation.Engaged {
		for i := range decisions {
			if decisions[i].Selected {
				stampKillSwitchRefusal(&decisions[i], boundaryObservation)
				metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressKillSwitch)
			}
		}
		m.Log.Info("kill-switch refused route preparation",
			"tenant", pol.Tenant, "namespace", e.namespace,
			"killSwitchEngaged", true, "killSwitchCause", string(boundaryObservation.Cause))
		return 0, nil, attempted
	}
	namespaceObservation := brakeState.observeNamespace(ctx, m, e.namespace)
	if ctx.Err() != nil {
		return 0, nil, attempted
	}
	if namespaceObservation.Engaged {
		for i := range decisions {
			if decisions[i].Selected {
				stampNamespaceDryRun(&decisions[i], namespaceObservation)
				metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressNamespaceDryRun)
			}
		}
		m.Log.Info("namespace dry-run refused route preparation",
			"tenant", pol.Tenant, "namespace", e.namespace,
			"actuationBrakeCause", namespaceObservation.Cause)
		return 0, nil, attempted
	}
	target := actuatorapi.TenantTarget{
		Tenant:         pol.Tenant,
		Namespace:      e.namespace,
		PolicyName:     e.key.Name,
		PolicyUID:      e.uid,
		Generation:     e.generation,
		Selector:       e.spec.Selector.DeepCopy(),
		EnabledActions: pol.EnabledActions,
	}
	var preparation actuatorapi.RoutePreparation
	var err error
	if prepared != nil {
		preparation = *prepared
	} else if preparation, err = m.actuation().PrepareRoutes(ctx, target); err == nil {
		if preparation.PhoenixErr != nil {
			m.Log.Error(preparation.PhoenixErr, "Phoenix route preparation refused", "tenant", pol.Tenant, "namespace", e.namespace)
		}
		if preparation.NativeErr != nil {
			m.Log.Error(preparation.NativeErr, "native route preparation refused", "tenant", pol.Tenant, "namespace", e.namespace)
		}
	}
	if ctx.Err() != nil {
		return 0, &preparation, attempted
	}
	if err != nil {
		m.Log.Error(err, "actuator EnsurePolicy failed; suppressing actuation this tick", "tenant", pol.Tenant)
		// T0-C: a tick-level pre-dispatch guard — every selected move is refused here.
		for i := range decisions {
			if decisions[i].Selected {
				stampDispatchEvidence(&decisions[i], model.DispatchNotAttempted, "ensure-policy-failed")
				metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressEnsurePolicy)
			}
		}
		return 0, &preparation, attempted
	}
	actuated := 0
	for i := range decisions {
		if !decisions[i].Selected {
			continue
		}
		// T0-C: every guard below stamps the dispatch outcome on the trace before
		// the audit write, so a selected-but-refused move never reads as unselected.
		stampDispatch := func(outcome, reason string) {
			stampDispatchEvidence(&decisions[i], outcome, reason)
		}
		if ctx.Err() != nil {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		// Inviolability guard at the emit boundary (defense in depth): a selected move is
		// ALWAYS feasible (the action-set generator excluded infeasible moves before
		// selection), but never emit one that is not — and shout if the invariant breaks.
		if !decisions[i].Feasible || decisions[i].Action == model.ActionNoop {
			m.Log.Error(nil, "INVARIANT VIOLATION: a selected move was infeasible/noop; refusing to emit",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			stampDispatch(model.DispatchNotAttempted, "inviolability-guard")
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressInviolability)
			continue
		}
		if prepErr := preparation.ForAction(m.routeBackend(), decisions[i].Action); prepErr != nil {
			m.Log.Error(prepErr, "action route preparation refused; suppressing dispatch", "tenant", pol.Tenant, "namespace", decisions[i].Namespace, "pod", decisions[i].Pod, "action", decisions[i].Action)
			stampDispatch(model.DispatchNotAttempted, "route-preparation-failed")
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressRoutePreparation)
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
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressMissingTickView)
			continue
		}
		if verdict := existentialEmitVerdict(decisions[i], v, pol); !verdict.Feasible {
			m.Log.Error(nil, "EMIT-BOUNDARY INVARIANT VETO: refusing infeasible move at actuate boundary",
				"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action, "reason", verdict.Reason)
			stampDispatch(model.DispatchNotAttempted, "emit-boundary-infeasible")
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressEmitBoundary)
			continue
		}
		// M-6 pre-submit gate: a code-exec injection (debugger/custom-inject) is submitted ONLY
		// after a FRESH admission re-verification (unexpired + matching epoch + target in verified
		// scope). This closes most of the gate-to-submit window; the residual race is covered by
		// the API-server VAP as the durable enforcement. Fail-closed: an unwired verifier or an
		// unverified policy refuses the dispatch. Guards BOTH the direct dispatch here and any
		// queued work that reaches this boundary.
		if decisions[i].Action == model.ActionDebugger || decisions[i].Action == model.ActionCustomInject {
			if m.CodeExec == nil {
				m.Log.Error(nil, "M-6 FAIL-CLOSED: code-exec verifier unwired; refusing ephemeral-container injection",
					"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
				stampDispatch(model.DispatchNotAttempted, "code-exec-unverified")
				metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressCodeExecUnverified)
				continue
			}
			ok, why := m.CodeExec.FinalCheck(ctx, decisions[i].Namespace)
			if ctx.Err() != nil {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "context-cancelled")
				return actuated, &preparation, attempted
			}
			if !ok {
				m.Log.Error(nil, "M-6 FAIL-CLOSED: code-exec admission not verified at pre-submit; refusing injection",
					"pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action, "reason", why)
				stampDispatch(model.DispatchNotAttempted, "code-exec-unverified")
				metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressCodeExecUnverified)
				continue
			}
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
		// Capture immutable target identity before a handler can delete the Pod.
		eventTarget := actuationEventTarget(v)
		dispatchObservation := state.observe(ctx, m.KillSwitch)
		if ctx.Err() != nil {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		if dispatchObservation.Engaged {
			stampKillSwitchRefusal(&decisions[i], dispatchObservation)
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressKillSwitch)
			m.Log.Info("kill-switch refused selected dispatch",
				"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
				"pod", decisions[i].Pod, "action", decisions[i].Action,
				"killSwitchEngaged", true, "killSwitchCause", string(dispatchObservation.Cause))
			continue
		}
		namespaceObservation = brakeState.observeNamespace(ctx, m, decisions[i].Namespace)
		if ctx.Err() != nil {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		if namespaceObservation.Engaged {
			stampNamespaceDryRun(&decisions[i], namespaceObservation)
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressNamespaceDryRun)
			m.Log.Info("namespace dry-run refused selected dispatch",
				"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
				"pod", decisions[i].Pod, "action", decisions[i].Action,
				"actuationBrakeCause", namespaceObservation.Cause)
			continue
		}
		podObservation := brakeState.observePod(ctx, m, decisions[i].Namespace, decisions[i].Pod, v.Pod.UID)
		if ctx.Err() != nil {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		if podObservation.Engaged {
			stampTargetBrake(&decisions[i], podObservation)
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressPodOptOut)
			m.Log.Info("Pod opt-out refused selected dispatch",
				"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
				"pod", decisions[i].Pod, "action", decisions[i].Action,
				"actuationBrakeCause", podObservation.Cause)
			continue
		}
		if ctx.Err() != nil {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		if (decisions[i].Action == model.ActionSensitiveOutputPolicyActivate || decisions[i].Action == model.ActionVoiceMemoryNoteRevoke || decisions[i].Action == model.ActionVoiceRefundPairDeny || decisions[i].Action == model.ActionVoiceOutputPolicyActivate || decisions[i].Action == model.ActionVoiceSessionAdmissionEnforce || decisions[i].Action == model.ActionVoiceMCPToolPin ||
			decisions[i].Action == model.ActionLiteLLMClientRevoke || decisions[i].Action == model.ActionEndpointLeaseRevoke || decisions[i].Action == model.ActionAdapterRotate ||
			decisions[i].Action == model.ActionCRMRefundRevoke) &&
			(decisions[i].Trace == nil || decisions[i].Trace.DecisionID == "" || pol.TickID == "") {
			recordExistentialEffect(&decisions[i], false)
			reason := "sensitive-output-selection-id-unavailable"
			if decisions[i].Action == model.ActionVoiceMemoryNoteRevoke {
				reason = "voice-memory-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionVoiceRefundPairDeny {
				reason = "voice-refund-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionVoiceMCPToolPin {
				reason = "voice-mcp-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionVoiceSessionAdmissionEnforce {
				reason = "voice-admission-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionVoiceOutputPolicyActivate {
				reason = "voice-output-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionAdapterRotate {
				reason = "adapter-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionLiteLLMClientRevoke {
				reason = "litellm-client-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionEndpointLeaseRevoke {
				reason = "endpoint-lease-selection-id-unavailable"
			} else if decisions[i].Action == model.ActionCRMRefundRevoke {
				reason = "crm-refund-selection-id-unavailable"
			}
			stampDispatch(model.DispatchNotAttempted, reason)
			continue
		}
		if m.EndpointLeaseAuthorityEnabled && decisions[i].Namespace == endpointlease.Namespace &&
			(m.OperatorNamespace == "" || m.BoundaryReader == nil || v.Pod.UID == "") {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "protected-endpoint-lease-journal-authority-unavailable")
			continue
		}
		if m.OperatorNamespace != "" && m.BoundaryReader != nil && v.Pod.UID != "" {
			fence := func(kind actuatorapi.PendingKind) (bool, error) {
				return m.actuation().PendingOperation(ctx, actuatorapi.PendingOperation{Kind: kind,
					Namespace: decisions[i].Namespace, Pod: decisions[i].Pod, PodUID: v.Pod.UID})
			}
			pendingLease, leaseFenceErr := fence(actuatorapi.PendingEndpointLease)
			if leaseFenceErr != nil || pendingLease {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "protected-endpoint-lease-operation-unresolved")
				m.Log.Info("same-Pod protected endpoint lease operation fences dispatch",
					"namespace", decisions[i].Namespace, "pod", decisions[i].Pod,
					"action", decisions[i].Action, "error", leaseFenceErr)
				continue
			}
			pendingClient, clientFenceErr := fence(actuatorapi.PendingLiteLLMClient)
			if clientFenceErr != nil || pendingClient {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "protected-owned-client-operation-unresolved")
				m.Log.Info("same-Pod protected owned-client operation fences dispatch",
					"namespace", decisions[i].Namespace, "pod", decisions[i].Pod,
					"action", decisions[i].Action, "error", clientFenceErr)
				continue
			}
			pendingAdmission, admissionFenceErr := fence(actuatorapi.PendingVoiceAdmission)
			if admissionFenceErr != nil || pendingAdmission {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "protected-voice-admission-operation-unresolved")
				continue
			}

			pendingVoiceOutput, voiceOutputFenceErr := fence(actuatorapi.PendingVoiceOutput)
			if voiceOutputFenceErr != nil || pendingVoiceOutput {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "protected-voice-output-operation-unresolved")
				continue
			}
			pending, fenceErr := fence(actuatorapi.PendingOutputPolicy)
			if fenceErr != nil || pending {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "protected-output-policy-operation-unresolved")
				m.Log.Info("same-Pod protected output policy operation fences dispatch",
					"namespace", decisions[i].Namespace, "pod", decisions[i].Pod,
					"action", decisions[i].Action, "error", fenceErr)
				continue
			}
		} else if decisions[i].Action == model.ActionEndpointLeaseRevoke {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "protected-endpoint-lease-journal-authority-unavailable")
			continue
		} else if decisions[i].Action == model.ActionSensitiveOutputPolicyActivate {
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "protected-output-policy-journal-authority-unavailable")
			continue
		}
		var capacityReservation *sharedcapacity.Reservation
		if m.SharedCapacity != nil {
			capacityRequest := sharedCapacityRequest(pol, decisions[i], v)
			var capacityErr error
			if inheritedReservation != nil {
				// From this point an exchange may have committed even when its API
				// acknowledgement is lost. Never separately release the old key.
				inheritedHandled = true
				capacityReservation, capacityErr = m.SharedCapacity.Exchange(ctx, inheritedReservation, capacityRequest)
			} else {
				capacityReservation, capacityErr = m.SharedCapacity.Acquire(ctx, capacityRequest)
			}
			if capacityErr != nil {
				stampDispatch(model.DispatchNotAttempted, "shared-capacity-refused")
				recordExistentialEffect(&decisions[i], false)
				m.Log.Error(capacityErr, "shared capacity refused dispatch before actuator invocation",
					"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
					"pod", decisions[i].Pod, "action", decisions[i].Action)
				continue
			}
			if capacityReservation != nil && !capacityReservation.Created {
				// The exact durable identity was observed after a restart or lost
				// response. Reconcile it through inventory; never replay mutation.
				stampDispatch(model.DispatchNotAttempted, "shared-capacity-operation-already-recorded")
				recordExistentialEffect(&decisions[i], false)
				continue
			}
		}
		if ctx.Err() != nil {
			if capacityReservation != nil && m.SharedCapacity != nil {
				if releaseErr := releaseSharedCapacityNoEffect(ctx, m.SharedCapacity, capacityReservation); releaseErr != nil {
					m.Log.Error(releaseErr, "shared capacity reservation retained after cancelled pre-dispatch")
				}
			}
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		if capacityReservation != nil && m.SharedCapacity != nil {
			// Only an acknowledged reserved -> dispatching CAS licenses the
			// backend call. A failed acknowledgement is ambiguous: the write may
			// have committed, so neither dispatch nor release is safe here. The
			// next inventory pass clears a still-reserved record or retains a
			// dispatching record for effect reconciliation.
			if claimErr := m.SharedCapacity.Claim(ctx, capacityReservation); claimErr != nil {
				stampDispatch(model.DispatchNotAttempted, "shared-capacity-claim-unconfirmed")
				recordExistentialEffect(&decisions[i], false)
				m.Log.Error(claimErr, "shared capacity dispatch claim was not acknowledged; backend invocation refused",
					"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
					"pod", decisions[i].Pod, "action", decisions[i].Action)
				continue
			}
		}
		actuationStarted := time.Now()
		recordExistentialEffect(&decisions[i], true)
		request := actuatorapi.Request{
			AdapterObservation:        v.Pod.AdapterObservation,
			OutputPolicyObservation:   v.Pod.OutputPolicyObservation,
			VoiceMemoryObservation:    v.Pod.VoiceMemoryObservation,
			VoiceRefundObservation:    v.Pod.VoiceRefundObservation,
			VoiceMCPObservation:       v.Pod.VoiceMCPObservation,
			VoiceOutputObservation:    v.Pod.VoiceOutputObservation,
			VoiceAdmissionObservation: v.Pod.VoiceAdmissionObservation,
			LiteLLMClientObservation:  v.Pod.LiteLLMClientObservation,
			EndpointLeaseObservation:  v.Pod.EndpointLeaseObservation,
			CRMRefundObservation:      v.Pod.CRMRefundObservation,
			PolicyName:                pol.PolicyName,
			PolicyUID:                 pol.PolicyUID,
			PolicyGeneration:          pol.PolicyGeneration,
			MaxGracePeriodSeconds:     pol.MaxGracePeriodSeconds,
			Tenant:                    pol.Tenant,
			Namespace:                 decisions[i].Namespace,
			Pod:                       decisions[i].Pod,
			Action:                    decisions[i].Action,
			Reason:                    decisions[i].Reason,
			Score:                     score,
			CoverageValue:             coverageValue,
			TargetUID:                 v.Pod.UID,
			TickID:                    pol.TickID,
			ServingObservation: &actuatorapi.ServingSelectionObservation{
				KVReset: v.Pod.KVResetEpoch, KVMigrate: v.Pod.KVMigrateEpoch,
				KVLocalEffect: v.Pod.KVLocalEffectEpoch, Guardrail: v.Pod.GuardrailEpochObservation,
			},
		}
		if decisions[i].Action == model.ActionRouteRotate || decisions[i].Action == model.ActionEndpointRotate || decisions[i].Action == model.ActionAdapterRotate ||
			decisions[i].Action == model.ActionSensitiveOutputPolicyActivate ||
			decisions[i].Action == model.ActionVoiceMemoryNoteRevoke ||
			decisions[i].Action == model.ActionVoiceRefundPairDeny ||
			decisions[i].Action == model.ActionVoiceOutputPolicyActivate || decisions[i].Action == model.ActionVoiceSessionAdmissionEnforce ||
			decisions[i].Action == model.ActionVoiceMCPToolPin ||
			decisions[i].Action == model.ActionLiteLLMClientRevoke ||
			decisions[i].Action == model.ActionEndpointLeaseRevoke ||
			decisions[i].Action == model.ActionCRMRefundRevoke {
			if decisions[i].Trace != nil {
				request.OperationID = decisions[i].Trace.DecisionID
			}
		}
		var res actuatorapi.Result
		var err error
		backendInvoked := true
		if ctx.Err() != nil {
			if capacityReservation != nil && m.SharedCapacity != nil {
				if releaseErr := releaseSharedCapacityNoEffect(ctx, m.SharedCapacity, capacityReservation); releaseErr != nil {
					m.Log.Error(releaseErr, "shared capacity reservation retained after acknowledged claim but before backend invocation")
				}
			}
			recordExistentialEffect(&decisions[i], false)
			stampDispatch(model.DispatchNotAttempted, "context-cancelled")
			return actuated, &preparation, attempted
		}
		res, backendInvoked, err = m.actuation().Actuate(ctx, request)
		attempted = attempted || backendInvoked
		if !backendInvoked {
			if capacityReservation != nil && m.SharedCapacity != nil {
				if releaseErr := releaseSharedCapacityNoEffect(ctx, m.SharedCapacity, capacityReservation); releaseErr != nil {
					m.Log.Error(releaseErr, "shared capacity reservation retained after backend pre-invocation refusal")
				}
			}
			if ctx.Err() != nil {
				recordExistentialEffect(&decisions[i], false)
				stampDispatch(model.DispatchNotAttempted, "context-cancelled")
				return actuated, &preparation, attempted
			}
			stampDispatch(model.DispatchNotAttempted, "quarantine-capacity-refused")
			recordExistentialEffect(&decisions[i], false)
			metrics.RecordActuationSuppression(pol.Tenant, string(decisions[i].Action), metrics.SuppressQuarantineCapacity)
			m.Log.Error(err, "quarantine capacity refused dispatch before actuator invocation",
				"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
				"pod", decisions[i].Pod, "action", decisions[i].Action)
			continue
		}
		// [M-18] Preserve the Phoenix forensic identity of THIS attempt BEFORE any branch,
		// so a result carrying real identifiers alongside an error keeps the facts the
		// adapter actually supplied while the failure outcome stays exactly as it was.
		// This mirrors, for the Phoenix payload, what M-48 does for the native fields
		// inside the error branch below. Assigning unconditionally also clears any payload
		// from a previous attempt on a reused decision, so a refused or retried move can
		// never inherit a stale reference. phoenixForensics allocates per decision and
		// returns nil when nothing was supplied — absence stays absent rather than
		// becoming empty strings.
		decisions[i].Phoenix = phoenixForensics(res, decisions[i].Namespace)
		disposition := noEffectDisposition(res, err)
		contradictoryDisposition := contradictoryNoEffectResult(res, err)
		definiteNoEffect := !contradictoryDisposition && (disposition == actuatorapi.NoEffectRefused || disposition == actuatorapi.NoEffectSatisfied || disposition == actuatorapi.NoEffectReconciled || disposition == actuatorapi.NoEffectDeclared)
		metrics.RecordActuationAttempt(pol.Tenant, string(decisions[i].Action), actuationAttemptOutcome(res, err, disposition, contradictoryDisposition))
		// M-11 emission-window bookkeeping remains conservative about any producer that
		// reports an attempted emission. Success, intent and learning accounting below
		// additionally require a coherent result.
		if res.Emitted {
			m.emissionWindow(e, 1, time.Now())
		}
		if err == nil && res.Emitted && !contradictoryDisposition && disposition == actuatorapi.NoEffectUnknown &&
			res.MutationKind == "forward-only" && res.RollbackRef == "" && len(res.ObjectsTouched) == 1 &&
			res.ObjectsTouched[0] == "Pod/"+request.Namespace+"/"+request.Pod && decisions[i].Action == model.ActionRotate &&
			actuatorUsesNativeRotate(m.actuation()) && m.ScopedOutcomeProducer != nil {
			// The producer hook only binds a previously authenticated synthetic
			// session. It queues work without network or durable I/O on this tick.
			m.ScopedOutcomeProducer.RecordNativeRotate(pol, v, request, res, time.Now())
		}
		m.notifyActuation(eventTarget, decisions[i].Action, res, err)
		if err != nil || disposition == actuatorapi.NoEffectRefused || contradictoryDisposition {
			fallbackObservation := state.observe(ctx, m.KillSwitch)
			fallbackBlocked := fallbackObservation.Engaged
			fallbackBrake := brakeState.observeNamespace(ctx, m, decisions[i].Namespace)
			if !fallbackBrake.Engaged {
				fallbackBrake = brakeState.observePod(ctx, m, decisions[i].Namespace, decisions[i].Pod, v.Pod.UID)
			}
			if fallbackBrake.Engaged {
				fallbackBlocked = true
				decisions[i].ActuationBrakeCause = fallbackBrake.Cause
				if decisions[i].Trace != nil {
					decisions[i].Trace.ActuationBrakeCause = fallbackBrake.Cause
				}
				m.Log.Info("actuation brake refused failure learning and fallback dispatch",
					"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
					"pod", decisions[i].Pod, "action", decisions[i].Action,
					"actuationBrakeCause", fallbackBrake.Cause)
			}
			if fallbackObservation.Engaged {
				decisions[i].KillSwitch = true
				decisions[i].KillSwitchCause = string(fallbackObservation.Cause)
				if decisions[i].Measurements != nil {
					decisions[i].Measurements.KillSwitch = model.OptionalBool{Present: true, Value: true}
				}
				if decisions[i].Trace != nil {
					decisions[i].Trace.KillSwitchEngaged = true
					decisions[i].Trace.KillSwitchCause = string(fallbackObservation.Cause)
				}
				m.Log.Info("kill-switch refused failure learning and fallback dispatch",
					"tenant", pol.Tenant, "namespace", decisions[i].Namespace,
					"pod", decisions[i].Pod, "action", decisions[i].Action,
					"killSwitchEngaged", true, "killSwitchCause", string(fallbackObservation.Cause))
			}
			// A canceled parent context belongs to the whole tick, not this
			// action's capability. An action-local timeout with a clean result
			// still counts toward later-tick feedback, but cannot license an
			// immediate different mutation. Partial effects enter neither gate.
			if !fallbackBlocked && !contradictoryDisposition && cleanNoEffectResult(res) && ctx.Err() == nil &&
				disposition != actuatorapi.NoEffectSatisfied && disposition != actuatorapi.NoEffectReconciled && disposition != actuatorapi.NoEffectDeclared &&
				m.ownerCurrent(pol.Owner(), m.tickEpochs[pol.Owner()]) {
				failureNow := time.Now()
				if m.FailureNow != nil {
					failureNow = m.FailureNow()
				}
				m.Failures.observe(failureKey{pol.Owner(), v.Pod.Namespace, v.Pod.UID, decisions[i].Action}, failureNow)
			}
			// Retain partial native writes without promoting an error to success.
			decisions[i].Handler = res.Handler
			decisions[i].ObjectsTouched = res.ObjectsTouched
			decisions[i].RollbackRef = res.RollbackRef
			decisions[i].MutationKind = res.MutationKind
			decisions[i].GracefulTermination = cloneGracefulTermination(res.GracefulTermination)
			decisions[i].DrainOperation = model.CloneDrainOperationEvidence(res.DrainOperation)

			outcome := slo.OutcomeFailed
			dispatchOutcome := model.DispatchError
			dispatchReason := "outcome-unknown"
			if disposition == actuatorapi.NoEffectRefused {
				outcome = slo.OutcomeNotEmitted
				dispatchOutcome = model.DispatchRefused
				dispatchReason = "definite-no-effect-refusal"
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				outcome = slo.OutcomeDeadlineExpired
				dispatchReason = "deadline-expired"
			}
			if fallbackBlocked {
				if fallbackObservation.Engaged {
					dispatchReason += "; fallback-blocked-kill-switch"
				}
				if fallbackBrake.Engaged {
					dispatchReason += "; fallback-blocked-actuation-brake"
				}
			}
			stampDispatch(dispatchOutcome, dispatchReason)
			m.recordActionOutcome(pol.Tenant, v, decisions[i].Action, pol.MinAvailableReplicas, actuationStarted, time.Now(), outcome)
			if err != nil {
				m.Log.Error(err, "actuate failed", "pod", decisions[i].Namespace+"/"+decisions[i].Pod)
			} else if disposition == actuatorapi.NoEffectRefused {
				m.Log.Info("actuator refused without effect", "pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			} else {
				m.Log.Error(nil, "actuator returned contradictory result evidence", "pod", decisions[i].Namespace+"/"+decisions[i].Pod, "action", decisions[i].Action)
			}
			reservationTransferred := false
			if !fallbackBlocked && allowFallback && m.ownerCurrent(pol.Owner(), m.tickEpochs[pol.Owner()]) &&
				ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
				disposition == actuatorapi.NoEffectRefused {
				if brain := m.brain(); brain.GatesCandidates() {
					targetKey := v.Pod.Namespace + "/" + v.Pod.Name
					if alternative, ok := brain.SelectAlternative(pol.Owner(), targetKey, decisions[i].Action); ok {
						if !brain.ReserveAlternative(pol.Owner(), targetKey, decisions[i].Action, alternative.Action) {
							decisions[i].DispatchReason += "; alternative-deferred-reservation-changed"
							if decisions[i].Trace != nil {
								decisions[i].Trace.DispatchReason = decisions[i].DispatchReason
							}
							continue
						}
						fallback := fallbackDecision(decisions[i], alternative)
						attempt := []model.Decision{fallback}
						reservationTransferred = capacityReservation != nil
						more, _, fallbackAttempted := m.actuatePreparedModeWithCapacity(ctx, e, pol, attempt, tickViewByKey, false, state, brakeState, capacityReservation, &preparation)
						attempted = attempted || fallbackAttempted
						actuated += more
						// The recursive call modifies its local slice's owned trace;
						// capture that actual attempt as a separate audit decision.
						m.fallbackDecisions = append(m.fallbackDecisions, attempt[0])
					} else {
						decisions[i].DispatchReason += "; alternative-deferred-no-admissible-candidate"
						if decisions[i].Trace != nil {
							decisions[i].Trace.DispatchReason = decisions[i].DispatchReason
						}
					}
				}
			}
			if capacityReservation != nil && !reservationTransferred && m.SharedCapacity != nil {
				if definiteNoEffect {
					if releaseErr := releaseSharedCapacityNoEffect(ctx, m.SharedCapacity, capacityReservation); releaseErr != nil {
						appendDispatchReason(&decisions[i], "shared-capacity-release-pending")
						m.Log.Error(releaseErr, "shared capacity no-effect release was not acknowledged")
					}
				} else if retainErr := m.SharedCapacity.RetainUnknown(ctx, capacityReservation); retainErr != nil {
					appendDispatchReason(&decisions[i], "shared-capacity-unknown-retention-unconfirmed")
					m.Log.Error(retainErr, "shared capacity unknown outcome retention was not acknowledged")
				}
			}
			continue
		}
		var capacityFinalizeErr error
		if capacityReservation != nil && m.SharedCapacity != nil && !res.Emitted {
			if definiteNoEffect {
				if capacityFinalizeErr = releaseSharedCapacityNoEffect(ctx, m.SharedCapacity, capacityReservation); capacityFinalizeErr != nil {
					m.Log.Error(capacityFinalizeErr, "shared capacity no-effect release was not acknowledged")
				}
			} else if capacityFinalizeErr = m.SharedCapacity.RetainUnknown(ctx, capacityReservation); capacityFinalizeErr != nil {
				m.Log.Error(capacityFinalizeErr, "shared capacity unknown outcome retention was not acknowledged")
			}
		}
		if res.Emitted {
			m.Failures.reset(failureKey{pol.Owner(), v.Pod.Namespace, v.Pod.UID, decisions[i].Action})
			stampDispatch(model.DispatchEmitted, "emitted-unconfirmed")
			decisions[i].Actuated = true
			recordExistentialEffect(&decisions[i], true)
			// M-23: stamp per-action emit intent on the SUCCESSFUL-emit path (a failed actuation
			// takes the `continue` above and never reaches here, so it can't throttle its own
			// retry). This closes the cross-tick burst hole — the next tick's guard reads this
			// intent via min(observed-since, intent-since) before the observed `*-epoch` clock
			// catches up. "" (an ungoverned action) is a no-op inside Mark.
			// [M-140 R4.1] The emit intent is OWNER-keyed, like every other slot store: the
			// next tick reads it back through Intents.Since(pol.Owner(), ...) and both the
			// per-tick GC and lifecycle cleanup prune it with RetainOwner. Marking it under
			// the raw display name wrote it where nothing reads, silently disabling the
			// cross-tick emission cooldown and leaking the entry past owner retirement.
			m.Intents.Mark(pol.Owner(), decisions[i].Namespace, decisions[i].Pod,
				feasibility.ExposureVarFor(decisions[i].Action), time.Now())
			// Carry the native actuator's forensic fields into the audit (empty for Phoenix).
			decisions[i].Handler = res.Handler
			decisions[i].ObjectsTouched = res.ObjectsTouched
			decisions[i].RollbackRef = res.RollbackRef
			decisions[i].MutationKind = res.MutationKind
			decisions[i].GracefulTermination = cloneGracefulTermination(res.GracefulTermination)
			decisions[i].DrainOperation = model.CloneDrainOperationEvidence(res.DrainOperation)
			actuated++
			metrics.RecordActuation(pol.Tenant, string(decisions[i].Action))
			if decisions[i].Action == model.ActionRotate {
				decisionID := ""
				if decisions[i].Trace != nil {
					decisionID = decisions[i].Trace.DecisionID
				}
				if !m.trackRotationReceipt(pol.Owner(), pol.Tenant, v, tickViewByKey, pol.MinAvailableReplicas, actuationStarted, res, decisionID) {
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
			// A non-emitted result can still carry reviewed handler identity or a
			// protected prior-operation reference. Retain those facts without
			// promoting them to a fresh actuation or success epoch.
			decisions[i].Handler = res.Handler
			decisions[i].ObjectsTouched = res.ObjectsTouched
			decisions[i].RollbackRef = res.RollbackRef
			decisions[i].MutationKind = res.MutationKind
			decisions[i].GracefulTermination = cloneGracefulTermination(res.GracefulTermination)
			decisions[i].DrainOperation = model.CloneDrainOperationEvidence(res.DrainOperation)
			switch disposition {
			case actuatorapi.NoEffectSatisfied:
				stampDispatch(model.DispatchSatisfied, "already-satisfied")
			case actuatorapi.NoEffectReconciled:
				stampDispatch(model.DispatchReconciled, "reconciled-prior-operation")
			case actuatorapi.NoEffectDeclared:
				stampDispatch(model.DispatchDeclared, "declared-without-implementation")
			default:
				stampDispatch(model.DispatchEmittedFalse, "outcome-unknown")
			}
			if capacityFinalizeErr != nil {
				if definiteNoEffect {
					appendDispatchReason(&decisions[i], "shared-capacity-release-pending")
				} else {
					appendDispatchReason(&decisions[i], "shared-capacity-unknown-retention-unconfirmed")
				}
			}
			m.recordActionOutcome(pol.Tenant, v, decisions[i].Action, pol.MinAvailableReplicas, actuationStarted, time.Now(), slo.OutcomeNotEmitted)
		}
	}
	return actuated, &preparation, attempted
}

// phoenixForensics maps the adapter's forensic identifiers into an owned, per-decision
// payload (M-18). EXPLICIT FIELD MAPPING ONLY — never a struct dump, so a field added to
// actuatorapi.Result later cannot silently widen the public audit record.
//
// namespace is the namespace of the request this result answers. The AMTD is namespaced
// and EnsurePolicy maintains it for exactly that namespace/tenant pair, so the namespace
// is attached only when an AMTD name actually exists; it is never guessed, and no AMTD
// UID is invented (the adapter does not read one back). Returns nil when the adapter
// supplied nothing at all, so a record shows honest absence instead of empty strings.
func phoenixForensics(res actuatorapi.Result, namespace string) *model.PhoenixForensics {
	p := model.PhoenixForensics{
		AMTDName:        res.AMTDName,
		EventName:       res.EventName,
		EventUID:        res.EventUID,
		RuleType:        res.RuleType,
		RuleThreatLevel: res.RuleThreatLevel,
		RuleSource:      res.RuleSource,
	}
	if p.AMTDName != "" {
		p.AMTDNamespace = namespace
	}
	if p.Empty() {
		return nil
	}
	return &p
}

func buildPolicy(e *policyEntry) model.Policy {
	s := &e.spec
	maxGracePeriodSeconds, maxGraceErr := s.EffectiveMaxGracePeriodSeconds()
	if maxGraceErr != nil {
		// Runtime inputs that bypass CRD validation remain invalid. Zero is a
		// refusal sentinel at the rotate boundary, never a force-delete value.
		maxGracePeriodSeconds = 0
	}
	disruptionAversion, disruptionAversionConfigured, disruptionAversionErr := s.EffectiveDisruptionAversion()
	if disruptionAversionErr != nil {
		disruptionAversion = math.NaN()
		disruptionAversionConfigured = true
	}
	normPreference, flowPreference, preferencesConfigured, preferencesErr := s.EffectiveCostPreferences()
	if preferencesErr != nil {
		normPreference = math.NaN()
		preferencesConfigured = true
	}
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
		PolicyGeneration:             e.generation,
		Mode:                         s.EffectiveMode(),
		DryRun:                       s.IsDryRun(),
		Lambda:                       s.EffectiveLambda(),
		DisruptionAversion:           disruptionAversion,
		DisruptionAversionConfigured: disruptionAversionConfigured,
		CostPreferencesConfigured:    preferencesConfigured,
		NormPreference:               normPreference, FlowPreference: flowPreference,
		NormSparsity:                 s.EffectiveNormSparsity(),
		FlowDisruption:               s.EffectiveFlowDisruption(),
		CostCeiling:                  s.EffectiveCostCeiling(),
		WeightSecrets:                s.EffectiveWeightSecrets(),
		BlastRadiusFromGraph:         s.AssetValue.BlastRadiusFromGraph,
		MaxMovesPerTick:              s.EffectiveMaxMovesPerTick(),
		MaxGracePeriodSeconds:        maxGracePeriodSeconds,
		TickInterval:                 s.EffectiveTickInterval(),
		AntiOverRotationWindow:       s.EffectiveAntiOverRotationWindow(),
		ProactiveFloor:               s.EffectiveProactiveFloor(),
		EventAgeHorizon:              s.EffectiveEventAgeHorizon(),
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
		AssetWeights:                 s.AssetLabelWeights(),
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
func (m *Manager) observeSourceHealth(e *policyEntry, read sensorapi.TelemetryResult) {
	health := read.Health
	source := health.Source
	var err error
	if read.Error != "" {
		err = errors.New(read.Error)
	}
	now := time.Now()
	m.mu.Lock()
	m.telemetrySource = source
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

// sourceOutageState returns a copy of the telemetry source's outage state, as of
// the last telemetry read.
func (m *Manager) sourceOutageState() (string, sourceOutage) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if st := m.degraded[m.telemetrySource]; st != nil {
		return m.telemetrySource, *st
	}
	return m.telemetrySource, sourceOutage{}
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
		if e.Trust == eventtrust.TrustTrusted {
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
			"untrusted", untrusted, "trustedDetectors", eventtrust.EventTrust().List(), "samples", samples, "unresolvedTargets", unresolved)
	case untrusted == 0 && was > 0:
		m.Log.Info("SecurityEvent stream is fully attributed again: every event carries an allowlisted creator", "previouslyUntrusted", was)
	}
}
