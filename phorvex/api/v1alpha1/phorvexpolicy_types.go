/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PhorvexPolicy is the PER-TENANT configuration surface for the Phorvex MVP (P0).
// It is NAMESPACE-SCOPED from line one: each tenant (a namespace, or a vcluster
// projected as a namespace) owns its own PhorvexPolicy, so the decision engine,
// exposure clocks, move budget, metrics and actuation are all keyed by tenant and
// multi-tenancy is NOT a later retrofit.
//
// The spec field STRUCTURE mirrors the PRD PART 7 CRD verbatim (selector /
// objective / budget / slo / assetValue / triggers / actions / mode). The only
// representation choice that departs from the PRD's illustrative YAML is that the
// dimensionless [0,1] knobs (lambda, cost weights, asset weights) are DECIMAL
// STRINGS rather than bare floats — this is the established Phoenix convention
// (see Phoenix's AnomalyScore / EWMAAlpha / PanicThreshold, all *string) and it
// avoids float canonicalization in the apiserver. The proactive-floor budget field
// is named proactiveFloor per the PRD YAML (a.k.a. the "hygiene floor": the
// detection-independent minimum rotation cadence).
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=pxp;phorvex
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.status.tenant`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Selected",type=integer,JSONPath=`.status.selectedPods`
// +kubebuilder:printcolumn:name="Decisions",type=integer,JSONPath=`.status.decisionsTotal`
// +kubebuilder:printcolumn:name="Actions",type=string,JSONPath=`.status.conditions[?(@.type=="ActionsSupported")].message`
// +kubebuilder:printcolumn:name="LastTick",type=date,JSONPath=`.status.lastTickTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type PhorvexPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PhorvexPolicySpec   `json:"spec,omitempty"`
	Status PhorvexPolicyStatus `json:"status,omitempty"`
}

// ExistentialSpec controls the narrowly scoped M99 availability exception.
type ExistentialSpec struct {
	// MayBreachSLO permits only SLO/availability exceptions for qualified M99 full containment.
	// +kubebuilder:default=false
	MayBreachSLO bool `json:"mayBreachSLO,omitempty"`
}

// PhorvexPolicySpec is the desired Phorvex behavior for one tenant's workloads.
type PhorvexPolicySpec struct {
	Existential ExistentialSpec `json:"existential,omitempty"`
	// Tenant is the explicit tenant identity this policy governs. Empty defaults to
	// the policy's own namespace (the common single-namespace-per-tenant case). When
	// a vcluster projects a tenant, set Tenant to the vcluster/tenant id so exposure
	// clocks, the move budget and emitted CRs are partitioned by tenant rather than
	// by raw namespace. PER-TENANT FROM LINE ONE — never a retrofit.
	// +kubebuilder:validation:Optional
	Tenant string `json:"tenant,omitempty"`

	// Trust declares directional peer trust for the M-34 observational assessment.
	// Until M-140 supplies canonical policy identity, entries are effective tenant keys.
	// Missing or ambiguous membership never establishes trust.
	Trust TrustSpec `json:"trust,omitempty"`

	// Cover controls optional cover features. M-34 remains excluded from scoring
	// even if enabled while its weight and execution prerequisites are unresolved.
	Cover CoverSpec `json:"cover,omitempty"`

	// Selector chooses the pods this policy protects, including matchExpressions.
	// Only pods in this policy's namespace (tenant) that match are considered.
	// +kubebuilder:validation:Required
	Selector metav1.LabelSelector `json:"selector"`

	// Objective is the cost-weighted optimization objective: maximize
	// E[security] - lambda * E[switching-cost]. (PRD: objective{lambda,costWeights}.)
	// +kubebuilder:validation:Required
	Objective ObjectiveSpec `json:"objective"`

	// Budget bounds availability impact: at most MaxMovesPerTick mutations per
	// TickInterval, never the same pod faster than AntiOverRotationWindow, and a
	// detection-independent ProactiveFloor on rotation cadence. (PRD: budget{...}.)
	// +kubebuilder:validation:Required
	Budget BudgetSpec `json:"budget"`

	// SLO is the hard availability envelope; a move that would breach it is infeasible
	// and is never proposed. (PRD: slo{p99Ms,minTokensPerSec,minAvailableReplicas}.)
	// +kubebuilder:validation:Required
	SLO SLOSpec `json:"slo"`

	// AssetValue derives per-pod consequence weighting from labels, mounted secrets
	// and the blast-radius graph. (PRD: assetValue{...}.)
	// +kubebuilder:validation:Required
	AssetValue AssetValueSpec `json:"assetValue"`

	// Triggers selects the decision triggers: the event-driven path (consume the
	// SecurityEvent stream) and the always-on proactive exposure floor. (PRD:
	// triggers{eventDriven,killChainSource}.)
	// +kubebuilder:validation:Required
	Triggers TriggersSpec `json:"triggers"`

	// Actions is the enabled mutation vocabulary. Bounded rotate is native;
	// quarantine retains its Phoenix route; advanced actions are opt-in. (PRD:
	// actions{enabled}.)
	// +kubebuilder:validation:Required
	Actions ActionsSpec `json:"actions"`

	// Brain configures deterministic model parameters owned by the Phorvex decision
	// engine. Empty preserves the exact shipped model defaults.
	// +kubebuilder:validation:Optional
	Brain BrainSpec `json:"brain,omitempty"`

	// Belief configures the P(hold) belief layer (PHORVEXSEC-189 / M-143).
	// +kubebuilder:validation:Optional
	Belief BeliefSpec `json:"belief,omitempty"`

	// Mode is the safety gate. "dryRun" (the default) decides + logs + emits metrics
	// but NEVER actuates; "active" additionally drives Phoenix. P0 ships and runs in
	// dryRun. (PRD: mode: dryRun.)
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=dryRun;active
	// +kubebuilder:default=dryRun
	Mode string `json:"mode,omitempty"`
}

// BrainSpec is the policy-owned configuration surface for the deterministic brain.
type BrainSpec struct {
	// KillChain configures the semi-Markov stage hazard model.
	// +kubebuilder:validation:Optional
	KillChain KillChainSpec `json:"killChain,omitempty"`
}

// BeliefSpec configures the P(hold) belief layer.
type BeliefSpec struct {
	// ExposurePressureCap is p_max, the ceiling of the exposure-pressure term in the
	// capped noisy-OR pHold = betaMean + p(t)*(1-betaMean) with
	// p(t) = p_max*min(1, t_exp/T_exp) (M-143 ruling, form A). It keeps the Beta
	// posterior informative at every exposure age: d pHold / d betaMean = 1-p(t) >= 1-p_max > 0,
	// so pHold reaches 1 only when betaMean does. Decimal string strictly inside (0,1);
	// empty defaults to "0.5" in code.
	// INSUFFICIENT EVIDENCE — provisional 0.5, fit in T3-D against confirmed attacker-hold outcomes.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^$|^0\.[0-9]+$`
	// +kubebuilder:validation:XValidation:rule="self == '' || (double(self) > 0.0 && double(self) < 1.0)",message="exposurePressureCap must be strictly between 0 and 1"
	ExposurePressureCap string `json:"exposurePressureCap,omitempty"`
}

// KillChainSpec configures Weibull stage-transition hazards. Sojourn values are seconds;
// Shape is the dimensionless Weibull shape parameter. Every override must be positive.
type KillChainSpec struct {
	// +kubebuilder:validation:Optional
	SojournScaleSeconds SojournScaleSpec `json:"sojournScaleSeconds,omitempty"`
	// Shape is a positive decimal string. Empty preserves the shipped value 2.0.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^([1-9][0-9]*(\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$`
	Shape string `json:"shape,omitempty"`
}

// SojournScaleSpec gives the characteristic dwell of each kill-chain stage in seconds.
// Fields are explicit so the CRD validates every override and rejects misspelled stage names.
type SojournScaleSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	Recon int64 `json:"recon,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	Exploit int64 `json:"exploit,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	Persist int64 `json:"persist,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	Lateral int64 `json:"lateral,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	Impact int64 `json:"impact,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	GPUSideChannel int64 `json:"gpuSideChannel,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	ModelTheft int64 `json:"modelTheft,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	LLMJacking int64 `json:"llmJacking,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	PromptInjectPersist int64 `json:"promptInjectPersist,omitempty"`
}

// ObjectiveSpec is the cost-weighted objective. Legacy policies use adaptive
// runtime lambda; an explicit disruptionAversion opts into a fixed coefficient.
type ObjectiveSpec struct {
	// Lambda configures the initial seed of P1's per-tenant legacy runtime lambda,
	// which multiplies the dimensionless ECost score. Runtime state then adapts from
	// move-count pressure and is audited separately from this policy value. It is not
	// certified as an exact move-budget dual. Decimal string in [0,10], matching
	// the runtime controller's existing clamp; empty defaults to "0.6" in code.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^$|^(0|[1-9][0-9]*)(\.[0-9]+)?$`
	// +kubebuilder:validation:XValidation:rule="self == '' || double(self) <= 10.0",message="lambda must be between 0 and 10"
	Lambda string `json:"lambda,omitempty"`

	// DisruptionAversion is an optional fixed preference beta in utility per
	// normalized ECost unit. When present it replaces runtime lambda only in the
	// scoring objective; the legacy count-pressure controller continues to learn
	// independently. Explicit "0" is configured. Remove the field to restore
	// legacy scoring. Empty is equivalent to absence. Decimal string in [0,10].
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^$|^(0|[1-9][0-9]*)(\.[0-9]+)?$`
	// +kubebuilder:validation:XValidation:rule="self == '' || double(self) <= 10.0",message="disruptionAversion must be between 0 and 10"
	DisruptionAversion string `json:"disruptionAversion,omitempty"`

	// CostWeights splits the switching cost K = normSparsity*C_norm +
	// flowDisruption*C_flow (PRD §5.1B). Decimal strings; empty defaults to
	// {0.4,0.6} in code.
	// +kubebuilder:validation:Optional
	CostWeights CostWeights `json:"costWeights,omitempty"`
}

// CostWeights are the two switching-cost coefficients (PRD §5.1B).
type CostWeights struct {
	// NormSparsity weights C_norm = "how many variables move" (move as little as
	// possible). Decimal string; empty defaults to "0.4".
	// +kubebuilder:validation:Optional
	NormSparsity string `json:"normSparsity,omitempty"`

	// FlowDisruption weights the bounded dimensionless C_flow disruption-loss score.
	// Recovery, connection and GPU/LLM signals are normalized before aggregation.
	// Decimal string; empty defaults to "0.6".
	// +kubebuilder:validation:Optional
	FlowDisruption string `json:"flowDisruption,omitempty"`
}

// BudgetSpec bounds availability impact and forensic safety (PRD budget{...} + FR8).
type BudgetSpec struct {
	// MaxMovesPerTick is the per-tick mutation budget B (bounds availability impact).
	// Nil means omitted and defaults to 3; an explicit pointer to 0 means decide and
	// log without selecting an actuation. YAML/JSON remains maxMovesPerTick: <integer>;
	// direct Go constructors must supply an *int when overriding the default.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	MaxMovesPerTick *int `json:"maxMovesPerTick,omitempty"`

	// MaxGracePeriodSeconds bounds the graceful termination requested by the
	// native rotate handler. Nil defaults to 30 seconds. The handler still honors
	// a shorter workload grace period; this cap never authorizes a zero-grace
	// deletion or bypasses availability safeguards.
	//
	// This is intentionally a pointer so omission remains distinguishable from an
	// invalid explicit zero in direct/internal objects as well as at admission.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=300
	// +kubebuilder:default=30
	MaxGracePeriodSeconds *int64 `json:"maxGracePeriodSeconds,omitempty"`

	// TickInterval is the decision cadence. Empty defaults to 20s in code.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="tickInterval must be a positive duration"
	TickInterval metav1.Duration `json:"tickInterval,omitempty"`

	// AntiOverRotationWindow is the minimum gap before the SAME pod may be mutated
	// again — the forensic/evidence-retention guard (never wipe attack evidence
	// faster than this window). Empty defaults to 5m in code.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="antiOverRotationWindow must be a positive duration"
	AntiOverRotationWindow metav1.Duration `json:"antiOverRotationWindow,omitempty"`

	// ProactiveFloor (a.k.a. the hygiene floor) is the detection-independent
	// MAXIMUM exposure: a pod unchanged for longer than ProactiveFloor is eligible
	// for a proactive rotation regardless of any detector. This is the thesis signal
	// (FR5). Empty defaults to 1h in code.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="proactiveFloor must be a positive duration"
	ProactiveFloor metav1.Duration `json:"proactiveFloor,omitempty"`
}

// SLOSpec is the hard availability envelope (PRD slo{...}; FR2 feasibility).
type SLOSpec struct {
	// CostCeiling is the independent dimensionless hard ceiling applied to the
	// conformal switching-cost bound. It is not derived from objective weights.
	// [ESTIMATE-UNVALIDATED] Empty defaults to "1.2": one logical pod replacement
	// plus the provisional structural margin from PHVX-9a/9b.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^([1-9][0-9]*(\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$`
	// +kubebuilder:default="1.2"
	CostCeiling string `json:"costCeiling,omitempty"`

	// P99Ms is the p99 latency ceiling in milliseconds; a move whose predicted
	// post-move p99 exceeds this is infeasible. 0 = unconstrained.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	P99Ms int64 `json:"p99Ms,omitempty"`

	// MinTokensPerSec is the throughput floor for GPU/LLM workloads. 0 =
	// unconstrained (non-AI workloads).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	MinTokensPerSec int64 `json:"minTokensPerSec,omitempty"`

	// MinAvailableReplicas is the availability floor (a PodDisruptionBudget analogue):
	// a move that would drop readyReplicas below this is infeasible.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=1
	MinAvailableReplicas int `json:"minAvailableReplicas,omitempty"`

	// ── SLO error budgets (PHVX-60a) ────────────────────────────────────────────
	// The three fields above are THRESHOLDS: they say what "healthy" means at an
	// instant. The four below are BUDGETS: how much unhealthiness the window may
	// absorb in total. The SLO cost model needs budgets, because its unit is the
	// fraction of the remaining budget a move would spend.
	//
	// All four default to zero/empty, which means "not configured".
	// BudgetsConfigured() then reports false and the budget path stays switched
	// off, leaving existing behaviour unchanged. That is deliberate: a cluster
	// with no SLO budgets must decide exactly as it does today, not block every
	// move for want of a denominator.

	// Window is the rolling window the budgets below are stated over — the same
	// window the service's own SLO uses, e.g. 720h for "rolling 30 days". Zero
	// disables the budget path for this service.
	// +kubebuilder:validation:Optional
	Window metav1.Duration `json:"window,omitempty"`

	// AvailabilityBudget is how long in total, across Window, the workload may sit
	// below MinAvailableReplicas before its availability budget is exhausted.
	// Consumption is measured the same way: the summed time readyReplicas was under
	// the floor, whatever caused it.
	// +kubebuilder:validation:Optional
	AvailabilityBudget metav1.Duration `json:"availabilityBudget,omitempty"`

	// LatencyBudget is the fraction of requests in Window permitted to exceed
	// P99Ms, as a PRD-convention decimal string — "0.01" for the usual 99% target.
	// Empty disables the latency dimension.
	// +kubebuilder:validation:Optional
	LatencyBudget string `json:"latencyBudget,omitempty"`

	// DisruptionBudgetReplicaSeconds is the total unavailable replica-seconds
	// Window may absorb: replicas removed from service multiplied by how long they
	// stayed out. It is its own budget and is NOT derived from the objective cost
	// weights — the betas price a move against the objective, which is a different
	// question from what the SLO can afford.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	DisruptionBudgetReplicaSeconds int64 `json:"disruptionBudgetReplicaSeconds,omitempty"`

	// ReserveFraction is the share of each TOTAL budget that Phorvex may never
	// spend, as a decimal string in [0,1). It is withheld from the total before
	// consumption is subtracted, so the usable remainder is
	//
	//	usable = (1 - reserveFraction) * total - consumed
	//
	// A fraction of the TOTAL, not of the remainder: a fraction of the remainder
	// would shrink as the budget burns and so would never reserve anything.
	// Empty or unparseable means no reserve.
	// +kubebuilder:validation:Optional
	ReserveFraction string `json:"reserveFraction,omitempty"`
}

// AssetValueSpec derives per-pod consequence weighting (PRD assetValue{...}; FR3).
type AssetValueSpec struct {
	// FromLabels maps a label KEY to a map of label VALUE -> decimal-string weight,
	// e.g. {data-class: {restricted: "1.0", internal: "0.4", public: "0.1"}}. A pod's
	// label-derived value is the max matching weight across configured keys.
	// +kubebuilder:validation:Optional
	FromLabels map[string]LabelValueWeights `json:"fromLabels,omitempty"`

	// WeightSecrets adds this decimal-string weight per distinct mounted Secret
	// (read from the pod spec's volumes/envFrom — Phorvex never reads secret
	// CONTENTS). Empty defaults to "0.8".
	// +kubebuilder:validation:Optional
	WeightSecrets string `json:"weightSecrets,omitempty"`

	// BlastRadiusFromGraph folds the reachability/blast-radius graph score (over
	// NetworkPolicy + RBAC) into asset value when true.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	BlastRadiusFromGraph bool `json:"blastRadiusFromGraph,omitempty"`
}

// LabelValueWeights maps a label value to a decimal-string asset weight.
type LabelValueWeights map[string]string

// TriggersSpec selects which decision triggers are active (PRD triggers{...}; FR5).
type TriggersSpec struct {
	// EventDriven consumes the SecurityEvent stream (Falco/KubeArmor/Prometheus
	// integrators) as belief evidence when true.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	EventDriven bool `json:"eventDriven,omitempty"`

	// EventAgeHorizon is the linear evidence-memory horizon for SecurityEvents.
	// Event weight reaches zero at this age. Omission defaults independently to
	// one hour; it is not derived from the proactive movement cadence.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="1h"
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="eventAgeHorizon must be a positive duration"
	// +kubebuilder:validation:XValidation:rule="duration(self) <= duration('2562047h47m16.854775807s')",message="eventAgeHorizon exceeds the supported duration"
	EventAgeHorizon *metav1.Duration `json:"eventAgeHorizon,omitempty"`

	// ReactiveOnly suppresses PROACTIVE (exposure-only) moves: when true, an asset is
	// actionable ONLY while a real attack signal targets it (a non-Phorvex SecurityEvent,
	// a compromised neighbor, or an AI poison marker). The hygiene-floor proactive
	// rotation/quarantine cadence is disabled, so the workload stays CALM until attacked
	// and the response is a clean, attributable reaction. Default false preserves the
	// proactive moving-target-defense behavior.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	ReactiveOnly bool `json:"reactiveOnly,omitempty"`

	// KillChainSource is the allowlist of SecurityEvent .spec.rule.source values
	// that feed the kill-chain belief (e.g. ["FalcoIntegrator","prometheus"]). Empty
	// accepts all sources.
	// +kubebuilder:validation:Optional
	// +listType=atomic
	KillChainSource []string `json:"killChainSource,omitempty"`
}

// ActionsSpec is the enabled mutation vocabulary (PRD actions{enabled}).
type ActionsSpec struct {
	// Enabled is the subset of allowed actions. The default set is bounded native
	// rotate plus Phoenix quarantine; noop is always implicitly available.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Enabled []ActionType `json:"enabled,omitempty"`
}

// ActionType is stored policy vocabulary. Runtime support is separate: identity-rotate
// remains admitted for existing objects but is declared-only for a security effect and
// refused for new native/hybrid dispatch. Bounded rotate is native, quarantine
// maps to Phoenix Quarantine, and advanced/AI moves are opt-in. A nil/empty Enabled set defaults
// to rotate+quarantine.
// +kubebuilder:validation:Enum=rotate;quarantine;noop;debugger;custom-inject;identity-rotate;route-rotate;warm-swap;mig-rebind;kv-reset;endpoint-rotate;model-shard-replace;adapter-rotate;request-drain;guardrail-rotate;kv-migrate-invalidate;sensitive-output-policy-activate;voice-memory-note-revoke;disable
type ActionType string

const (
	// ActionRotate requests a native, policy-bounded graceful Pod eviction.
	// A pure Phoenix backend refuses this action because its Delete strategy cannot
	// carry maxGracePeriodSeconds.
	ActionRotate ActionType = "rotate"
	// ActionQuarantine maps to Phoenix's Quarantine action (deny-all + detach).
	ActionQuarantine ActionType = "quarantine"
	// ActionNoop is an explicit no-op (always available; used in counterfactuals).
	ActionNoop ActionType = "noop"

	// --- P-ACTUATOR native vocabulary (advanced K8s + AI/GPU; native-only, opt-in) ---
	ActionDebugger     ActionType = "debugger"
	ActionCustomInject ActionType = "custom-inject"
	// ActionIdentityRotate is retained for stored policy compatibility, not execution.
	ActionIdentityRotate                ActionType = "identity-rotate"
	ActionRouteRotate                   ActionType = "route-rotate"
	ActionWarmSwap                      ActionType = "warm-swap"
	ActionMIGRebind                     ActionType = "mig-rebind"
	ActionKVReset                       ActionType = "kv-reset"
	ActionEndpointRotate                ActionType = "endpoint-rotate"
	ActionModelShardReplace             ActionType = "model-shard-replace"
	ActionAdapterRotate                 ActionType = "adapter-rotate"
	ActionRequestDrain                  ActionType = "request-drain"
	ActionGuardrailRotate               ActionType = "guardrail-rotate"
	ActionSensitiveOutputPolicyActivate ActionType = "sensitive-output-policy-activate"
	ActionVoiceMemoryNoteRevoke         ActionType = "voice-memory-note-revoke"
	ActionLiteLLMClientRevoke           ActionType = "litellm-client-revoke"
	ActionKVMigrateInvalidate           ActionType = "kv-migrate-invalidate"
	ActionDisable                       ActionType = "disable"
)

// ModeDryRun decides + logs + emits metrics but never actuates (the P0 default).
const ModeDryRun = "dryRun"

// ModeActive additionally drives Phoenix (Phase 2 of the MVP; never auto-enabled
// in P0).
const ModeActive = "active"

// PhorvexPolicyStatus is the observed Phorvex state for this tenant.
type PhorvexPolicyStatus struct {
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Tenant echoes the effective tenant identity (Spec.Tenant or the namespace).
	// +kubebuilder:validation:Optional
	Tenant string `json:"tenant,omitempty"`

	// SelectedPods is the number of pods this policy currently protects.
	// +kubebuilder:validation:Optional
	SelectedPods int `json:"selectedPods,omitempty"`

	// LastTickTime is the wall-clock time of the most recent decision tick.
	// +kubebuilder:validation:Optional
	LastTickTime metav1.Time `json:"lastTickTime,omitempty"`

	// LastDecisionTime is when a non-noop move was last DECIDED (logged; in dryRun
	// not actuated).
	// +kubebuilder:validation:Optional
	LastDecisionTime metav1.Time `json:"lastDecisionTime,omitempty"`

	// DecisionsTotal is the cumulative count of decided non-noop moves.
	// +kubebuilder:validation:Optional
	DecisionsTotal int64 `json:"decisionsTotal,omitempty"`

	// MovesThisWindow counts observed emission acknowledgements in the trailing
	// AntiOverRotationWindow. It does not measure confirmed effects or control budgets.
	// While EmissionHistory is Unknown this is a lower bound, including zero.
	// History is in-memory and becomes complete after one fully observed window.
	// +kubebuilder:validation:Optional
	MovesThisWindow int `json:"movesThisWindow,omitempty"`

	// Actuated is true while at least one observed emission remains in the trailing
	// AntiOverRotationWindow. Dry-run/kill-switch changes preserve earlier emissions.
	// False with EmissionHistory Unknown is not proof of no emission before observation.
	// +kubebuilder:validation:Optional
	Actuated bool `json:"actuated,omitempty"`

	// KillSwitchEngaged reflects the global kill-switch (FR8): when engaged the
	// engine decides + logs but suppresses all actuation regardless of Mode.
	//
	// NOT omitempty (PHVX-17). With it, `false` was indistinguishable from "never written": the
	// field simply vanished, so an operator reading the CR could not tell a running defence from a
	// status that had never been reconciled. Measured on the live fleet — all four policies showed
	// the field ABSENT while the sentinel said engaged=false, i.e. the healthy case and the silent
	// case looked identical. An explicit `false` is the whole point of a safety-control readout.
	// +kubebuilder:validation:Optional
	KillSwitchEngaged bool `json:"killSwitchEngaged"`

	// Conditions includes Ready, DryRun, ValidationError, KillSwitch,
	// ActionsSupported, and ActuationPrepared (current tick's backend preparation).
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// PhorvexPolicyList contains a list of PhorvexPolicy.
type PhorvexPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PhorvexPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PhorvexPolicy{}, &PhorvexPolicyList{})
}

// TrustSpec is directional: A listing B does not make A trusted by B.
type TrustSpec struct {
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:MinLength=1
	PeerPolicies []string `json:"peerPolicies,omitempty"`
}

type CoverSpec struct {
	WarmSwap WarmSwapCoverSpec `json:"warmSwap,omitempty"`
}

type WarmSwapCoverSpec struct {
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
}
