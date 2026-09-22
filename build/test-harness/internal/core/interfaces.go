// Package core defines the durable, plugin-based contract for the Phoenix /
// Phorvex Kubernetes attack-and-benchmark harness.
//
// Two interfaces compose the whole system: Scenario (an attack kill-chain with a
// concrete success oracle) and Defender (a defensive actuator arm). Both are
// self-registering: a plugin is ONE file containing a func init() that calls
// RegisterScenario / RegisterDefender. The runner enumerates the package-level
// registries; there is NO central switch/list to edit when adding a plugin.
//
// Everything else in this package (the runner, metric schema, statistics and
// report generation) is GENERIC and agnostic to which attack/defense is plugged
// in. Adding a future attack or defender is one new file + one register call,
// with ZERO core changes.
package core

import (
	"context"
)

// Category classifies a scenario against the Phoenix/R6 marketing surface.
type Category string

const (
	// CategoryClassicChain is a classic, well-understood Kubernetes kill-chain
	// (escape, lateral movement, cred theft, C2/exfil, stealth dwell).
	CategoryClassicChain Category = "ClassicChain"
	// CategoryR6Claimed is an attack class R6 explicitly claims to cover; the
	// harness measures that claim against a concrete oracle with controls.
	CategoryR6Claimed Category = "R6Claimed"
	// CategoryModernUnsupported is a modern (often admission-/build-time) attack
	// class outside Phoenix's reactive pod-rotation actuator model.
	CategoryModernUnsupported Category = "ModernUnsupported"
)

// R6Tag is the honest, code-grounded verdict on whether the genuine Phoenix
// matcher path can respond to a scenario.
type R6Tag string

const (
	// R6Covers means the genuine reactive matcher path can disrupt the oracle
	// (typically emitter-dependent, but a real path exists).
	R6Covers R6Tag = "R6Covers"
	// R6Partial means Phoenix disrupts only opportunistically / as a side effect
	// of rotation, not by detection — the marketing claim overshoots the code.
	R6Partial R6Tag = "R6Partial"
	// R6CannotRespond means no matcher path applies; rotation cannot touch the
	// oracle (a genuine Phorvex differentiator).
	R6CannotRespond R6Tag = "R6CannotRespond"
)

// Capability is a cluster capability a scenario may REQUIRE. A scenario with no
// CapabilityRequirements runs anywhere (kind / EKS / CoreWeave / vcluster).
type Capability string

const (
	// CapGPU requires at least one node advertising nvidia.com/gpu allocatable.
	CapGPU Capability = "CapGPU"
	// CapMultiNode requires more than one schedulable node.
	CapMultiNode Capability = "CapMultiNode"
	// CapMIG requires NVIDIA MIG profile resources/labels.
	CapMIG Capability = "CapMIG"
)

// ScenarioRealism states what the implementation actually exercises. An empty
// value is deliberately treated as unassessed for legacy plugins and records.
type ScenarioRealism string

const (
	RealismUnassessed       ScenarioRealism = "unassessed"
	RealismMarkerSimulation ScenarioRealism = "marker-simulation"
	RealismExecutable       ScenarioRealism = "executable-mechanism"
)

// ScenarioMeta is the static descriptor every scenario advertises.
type ScenarioMeta struct {
	// Name is the stable plugin identifier (e.g. "c1-escape-persist").
	Name string
	// Category buckets the scenario for reporting.
	Category Category
	// Source documents where the scenario was extracted from (task / paper / page).
	Source string
	// R6ResponseTag is the honest, code-grounded R6 verdict.
	R6ResponseTag R6Tag
	// AttackTechniqueIDs are declared narrative mappings. They are not exercise
	// or defense-coverage claims; ExercisedTechniqueIDs carries the smaller set
	// directly supported by the implemented mechanism.
	AttackTechniqueIDs []string
	// ExercisedTechniqueIDs are supported by the executable mechanism. Empty is
	// honest for marker simulations and for legacy, unassessed scenarios.
	ExercisedTechniqueIDs []string
	// BenignControl marks a non-adversarial executable mechanism that exists to
	// measure one defensive side effect. It must not invent declared or exercised
	// ATT&CK mappings merely to satisfy catalogue shape.
	BenignControl bool
	// Realism classifies the implementation. Empty means unassessed.
	Realism ScenarioRealism
	// Mechanism describes the concrete setup/stimulus/oracle under test.
	Mechanism string
	// ClaimLimits states what a successful result cannot establish.
	ClaimLimits string
	// OracleDescription and CleanupDescription make the catalogue independently
	// reviewable without executing a scenario.
	OracleDescription  string
	CleanupDescription string
	// CapabilityRequirements are the cluster capabilities REQUIRED to run; unmet
	// requirements cause a skip-with-note (never a failure).
	CapabilityRequirements []Capability
	// R6Justification is the honest prose explaining the R6ResponseTag.
	R6Justification string
}

// EffectiveRealism converts legacy empty metadata to the explicit unassessed
// state. Callers must never infer executable coverage from an absent descriptor.
func (m ScenarioMeta) EffectiveRealism() ScenarioRealism {
	if m.Realism == "" {
		return RealismUnassessed
	}
	return m.Realism
}

// AttackResult is what Execute reports: the concrete stages it performed and
// the commands it issued (for provenance). It is intentionally evidence-rich and
// oracle-agnostic; the verdict lives in OracleResult.
type AttackResult struct {
	// Stages are the ordered implementation stages actually performed. Narrative
	// phases that were not executed must not appear here.
	Stages []string
	// Commands are the concrete commands/API calls issued (provenance).
	Commands []string
	// Notes is free-form attacker telemetry (e.g. observed rotation gaps).
	Notes map[string]string
	// BenchmarkEvidence is bounded, non-sensitive, machine-readable producer evidence.
	// It is preserved on the metric even when Execute returns an error, without
	// changing the trial verdict. Producers must not place credentials, secret
	// values, or unbounded payloads here.
	BenchmarkEvidence map[string]string
	// Skipped is true when the scenario could not run (capability unmet) and
	// SkipReason explains why.
	Skipped    bool
	SkipReason string
}

// OracleResult is the concrete, observable verdict on attack success. Achieved is
// measured strictly against the scenario's documented observable post-state.
type OracleResult struct {
	// Achieved is true iff the concrete observable success state was reached.
	Achieved bool
	// ObservedState is a human-readable description of the measured state.
	ObservedState string
	// Evidence carries the raw observable facts that justify Achieved (counts,
	// UIDs, HTTP statuses, marker contents).
	Evidence map[string]string
	// Skipped is true when the oracle could not be evaluated (capability unmet).
	Skipped    bool
	SkipReason string
}

// Scenario is the ONE interface every attack plugin implements. A scenario file
// self-registers via func init(){ RegisterScenario(&X{}) }.
type Scenario interface {
	// Metadata returns the static descriptor.
	Metadata() ScenarioMeta
	// Setup stages the target workload in the sandbox namespace.
	Setup(ctx context.Context, env *Env) error
	// Execute performs the attack kill-chain and returns what it did.
	Execute(ctx context.Context, env *Env) (AttackResult, error)
	// SuccessOracle measures the concrete observable success state.
	SuccessOracle(ctx context.Context, env *Env) (OracleResult, error)
	// Teardown is full, idempotent cleanup (safe to re-run).
	Teardown(ctx context.Context, env *Env) error
}

// DefenderMeta is the static descriptor every defender advertises.
type DefenderMeta struct {
	// Name is the stable plugin identifier (e.g. "d-fullphoenix").
	Name string
	// Description documents the defense and its honest limits.
	Description string
	// IsNegativeControlBaseline marks the NoMTD positive-control arm (undefended),
	// which anchors the 100% baseline that DisruptionVsOracle is measured against.
	IsNegativeControlBaseline bool
	// MeanRotationInterval is the arm's nominal rotation period in seconds (0 =
	// no rotation). The adaptive attacker uses it (and observed gaps) to plan.
	MeanRotationIntervalSeconds float64
}

// Defender is the ONE interface every defensive actuator implements. A defender
// file self-registers via func init(){ RegisterDefender(&X{}) }.
type Defender interface {
	// Metadata returns the static descriptor.
	Metadata() DefenderMeta
	// Setup stands up the defense (start operator + apply AMTD, or arm the timer).
	Setup(ctx context.Context, env *Env) error
	// Start activates the defense for the trial.
	Start(ctx context.Context, env *Env) error
	// Stop deactivates the defense.
	Stop(ctx context.Context, env *Env) error
	// Teardown is idempotent cleanup.
	Teardown(ctx context.Context, env *Env) error
}

// DefenseObserver is an OPTIONAL capability a defender may implement so the
// runner can attribute disruption to a concrete defensive action and count false
// defensive moves (for the negative control). A defender that does not implement
// it is treated as "no observable defensive action".
type DefenseObserver interface {
	// DefensiveActions returns the number of concrete defensive actions
	// (rotations / quarantines / deletes) the arm has taken since Start, and the
	// timestamps (unix seconds) of each — used for time-to-action and to learn
	// the rotation rhythm.
	DefensiveActions(ctx context.Context, env *Env) (count int, atUnix []float64, err error)
}

// DefenseEffectReceipt links a defender-owned action to one scenario objective
// and one attack attempt. It is optional: arms without a target-specific action
// cannot receive effect credit from a changed fixture state alone.
type DefenseEffectReceipt struct {
	Objective string
	TargetUID string
	AttemptID string
	AtUnix    float64
}

type DefenseEffectObserver interface {
	DefensiveEffectReceipt(ctx context.Context, env *Env) (DefenseEffectReceipt, error)
}

// TargetedActionRequest is the exact live object and finite observation window
// offered by a benign scenario after its application state has been established.
// Coordinators must re-read and bind every identity before adding the target
// label or sending an action. The label belongs only on the named live object,
// never on its controller template.
type TargetedActionRequest struct {
	Objective                         string
	Namespace                         string
	TargetKind                        string
	TargetName                        string
	TargetUID                         string
	TargetResourceVersion             string
	OwnerKind                         string
	OwnerName                         string
	OwnerUID                          string
	TargetLabelKey                    string
	TargetLabelValue                  string
	RequestedGraceSeconds             int64
	AvailabilityPolicyName            string
	AvailabilityPolicyUID             string
	AvailabilityPolicyResourceVersion string
	AvailabilitySelectorKey           string
	AvailabilitySelectorValue         string
	InitialMinAvailable               int
	EligibleMinAvailable              int
	SessionEstablishedUTC             string
	DeadlineUTC                       string
}

// TargetedActionResult retains the coordinator's bounded, sanitized receipts.
// A complete non-selection or refusal is data and returns no error. ReceiptJSON
// values are strict coordinator-owned schemas; they must exclude raw rationale,
// model inputs, credentials, and workload payloads. The scenario preserves them
// verbatim so independent decision/dispatch attribution is not inferred from an
// application effect.
type TargetedActionResult struct {
	SchemaVersion                     string
	Coordinator                       string
	StartedAtUTC                      string
	EndedAtUTC                        string
	Disposition                       string
	AttributionComplete               bool
	TargetName                        string
	TargetUID                         string
	TargetResourceVersion             string
	RequestedGraceSeconds             int64
	AvailabilityPolicyResourceVersion string
	ActionAtUTC                       string
	ControlReceiptJSON                string
	EligibleReceiptJSON               string
	AuthorizationReceiptJSON          string
}

// TargetedActionCoordinator is an optional scenario-to-defender handshake. It
// starts only after the scenario has established application state. Absence of
// this interface means the scenario observes a no-action arm for the same fixed
// window. Implementations may legitimately return a complete no-op result.
type TargetedActionCoordinator interface {
	CoordinateTargetedAction(ctx context.Context, env *Env, request TargetedActionRequest) (TargetedActionResult, error)
}

// TargetedActionScenario marks a scenario that performs the optional handshake.
// Coordinators use it to avoid starting a legacy broad action loop before the
// scenario has established and identified one exact target.
type TargetedActionScenario interface {
	UsesTargetedActionCoordination() bool
}
