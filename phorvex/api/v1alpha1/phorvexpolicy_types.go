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

// PhorvexPolicySpec is the desired Phorvex behavior for one tenant's workloads.
type PhorvexPolicySpec struct {
	// Tenant is the explicit tenant identity this policy governs. Empty defaults to
	// the policy's own namespace (the common single-namespace-per-tenant case). When
	// a vcluster projects a tenant, set Tenant to the vcluster/tenant id so exposure
	// clocks, the move budget and emitted CRs are partitioned by tenant rather than
	// by raw namespace. PER-TENANT FROM LINE ONE — never a retrofit.
	// +kubebuilder:validation:Optional
	Tenant string `json:"tenant,omitempty"`

	// Selector chooses the pods this policy protects (PRD: selector.matchLabels).
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

	// Actions is the enabled mutation vocabulary (a subset of {rotate,quarantine}).
	// In P0 these map to Phoenix's Delete (rotate) and Quarantine actions. (PRD:
	// actions{enabled}.)
	// +kubebuilder:validation:Required
	Actions ActionsSpec `json:"actions"`

	// Mode is the safety gate. "dryRun" (the default) decides + logs + emits metrics
	// but NEVER actuates; "active" additionally drives Phoenix. P0 ships and runs in
	// dryRun. (PRD: mode: dryRun.)
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=dryRun;active
	// +kubebuilder:default=dryRun
	Mode string `json:"mode,omitempty"`
}

// ObjectiveSpec is the cost-weighted objective (PRD objective{lambda,costWeights}).
type ObjectiveSpec struct {
	// Lambda is the cost weight in the objective E[security] - lambda*E[cost], as a
	// decimal string in [0,inf) (PRD example "0.6"). Larger lambda = more
	// cost-averse (rotate less). Empty defaults to "0.6" in code.
	// +kubebuilder:validation:Optional
	Lambda string `json:"lambda,omitempty"`

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

	// FlowDisruption weights C_flow = restart seconds / dropped connections /
	// (for GPU/LLM) KV-cache rebuild + warm-load. Decimal string; empty defaults
	// to "0.6".
	// +kubebuilder:validation:Optional
	FlowDisruption string `json:"flowDisruption,omitempty"`
}

// BudgetSpec bounds availability impact and forensic safety (PRD budget{...} + FR8).
type BudgetSpec struct {
	// MaxMovesPerTick is the per-tick mutation budget B (bounds availability impact).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	MaxMovesPerTick int `json:"maxMovesPerTick,omitempty"`

	// TickInterval is the decision cadence. Empty defaults to 20s in code.
	// +kubebuilder:validation:Optional
	TickInterval metav1.Duration `json:"tickInterval,omitempty"`

	// AntiOverRotationWindow is the minimum gap before the SAME pod may be mutated
	// again — the forensic/evidence-retention guard (never wipe attack evidence
	// faster than this window). Empty defaults to 5m in code.
	// +kubebuilder:validation:Optional
	AntiOverRotationWindow metav1.Duration `json:"antiOverRotationWindow,omitempty"`

	// ProactiveFloor (a.k.a. the hygiene floor) is the detection-independent
	// MAXIMUM exposure: a pod unchanged for longer than ProactiveFloor is eligible
	// for a proactive rotation regardless of any detector. This is the thesis signal
	// (FR5). Empty defaults to 1h in code.
	// +kubebuilder:validation:Optional
	ProactiveFloor metav1.Duration `json:"proactiveFloor,omitempty"`
}

// SLOSpec is the hard availability envelope (PRD slo{...}; FR2 feasibility).
type SLOSpec struct {
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
	// Enabled is the subset of allowed actions. P0 supports rotate (Phoenix Delete)
	// and quarantine (Phoenix Quarantine); noop is always implicitly available.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Enabled []ActionType `json:"enabled,omitempty"`
}

// ActionType is one enabled mutation. The native actuator (P-ACTUATOR) enacts the full
// vocabulary; rotate/quarantine also map to Phoenix Delete/Quarantine via the optional
// adapter. The advanced/AI moves are native-only and opt-in (a nil/empty Enabled set
// defaults to rotate+quarantine — the historical behaviour).
// +kubebuilder:validation:Enum=rotate;quarantine;noop;debugger;custom-inject;identity-rotate;route-rotate;warm-swap;mig-rebind;kv-reset;endpoint-rotate;model-shard-replace
type ActionType string

const (
	// ActionRotate maps to Phoenix's Delete action (kill+clean respawn).
	ActionRotate ActionType = "rotate"
	// ActionQuarantine maps to Phoenix's Quarantine action (deny-all + detach).
	ActionQuarantine ActionType = "quarantine"
	// ActionNoop is an explicit no-op (always available; used in counterfactuals).
	ActionNoop ActionType = "noop"

	// --- P-ACTUATOR native vocabulary (advanced K8s + AI/GPU; native-only, opt-in) ---
	ActionDebugger          ActionType = "debugger"
	ActionCustomInject      ActionType = "custom-inject"
	ActionIdentityRotate    ActionType = "identity-rotate"
	ActionRouteRotate       ActionType = "route-rotate"
	ActionWarmSwap          ActionType = "warm-swap"
	ActionMIGRebind         ActionType = "mig-rebind"
	ActionKVReset           ActionType = "kv-reset"
	ActionEndpointRotate    ActionType = "endpoint-rotate"
	ActionModelShardReplace ActionType = "model-shard-replace"
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

	// MovesThisWindow is the moves decided in the current AntiOverRotationWindow
	// (budget accounting).
	// +kubebuilder:validation:Optional
	MovesThisWindow int `json:"movesThisWindow,omitempty"`

	// Actuated is true once at least one move was really emitted to Phoenix (only
	// possible in active mode). Stays false for the whole P0 dry-run lifetime.
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

	// Conditions includes Ready, DryRun, ValidationError, KillSwitch, ActionsSupported.
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
