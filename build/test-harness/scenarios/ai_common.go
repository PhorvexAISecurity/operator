package scenarios

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ai_common.go is the SHARED plumbing for the Pass-B AI scenarios. Every AI
// scenario is ONE self-registering file that reuses these helpers so the
// split-oracle (in-request vs persistence), the genuine matcher trigger
// (injected panic/drift/timed via the existing Emitter), the rotation-target
// stamping, and the ADDITIVE metric evidence are stamped consistently. The
// mocks come from internal/mocks/ai_standins.go.

// aiOracle is the canonical builder for a split-oracle OracleResult. It records
// which half scored, the two halves' outcomes, the MEASURED MTD-effect inputs
// (persistence-disrupted / neutralized), the audit trigger attribution, and the
// AI threat IDs — all into Evidence so the runner lifts them onto the additive
// metric fields without an interface change.
const aiPersistenceWindow = 4 * time.Second

func aiEventAttribution(emitted bool) string {
	if emitted {
		return core.TriggerHarnessInjected
	}
	return core.TriggerDetectorAbsent
}

func aiEffectAttempt(env *core.Env, targetUID string) string {
	return fmt.Sprintf("%s/%s/%d/%s/%d", env.ScenarioName, env.DefenderName, env.Trial, targetUID, time.Now().UnixNano())
}

// aiDefenderEffect accepts a receipt only from the active defender and only
// after the actual fixture changed. Delivery, arm name and a golden digest on
// their own are insufficient. The runner additionally checks action count and
// timing before scoring a negative objective observation.
func aiDefenderEffect(ctx context.Context, env *core.Env, targetUID, attempt string, changed bool) map[string]string {
	ev := map[string]string{"effectAttempt": attempt, "defensiveEffectAttributed": "false"}
	if !changed {
		return ev
	}
	d, ok := core.LookupDefender(env.DefenderName)
	if !ok {
		return ev
	}
	obs, ok := d.(core.DefenseEffectObserver)
	if !ok {
		return ev
	}
	receipt, err := obs.DefensiveEffectReceipt(ctx, env)
	if err != nil {
		env.Log.Logf("ai effect receipt unavailable: %v", err)
		return ev
	}
	ev["defensiveActionTargetUID"] = receipt.TargetUID
	ev["defensiveActionAttempt"] = receipt.AttemptID
	ev["defensiveEffectObjective"] = receipt.Objective
	ev["defensiveActionAtUnix"] = fmt.Sprintf("%.9f", receipt.AtUnix)
	startedNanos, parseErr := strconv.ParseInt(attempt[strings.LastIndex(attempt, "/")+1:], 10, 64)
	startedAt := float64(startedNanos) / float64(time.Second)
	if parseErr == nil && receipt.Objective == env.ScenarioName && receipt.TargetUID == targetUID && receipt.AttemptID == attempt && receipt.AtUnix >= startedAt && receipt.AtUnix <= float64(time.Now().UnixNano())/float64(time.Second) {
		ev["defensiveEffectAttributed"] = "true"
	}
	return ev
}

func aiMergeEvidence(base, effect map[string]string) map[string]string {
	for k, v := range effect {
		base[k] = v
	}
	return base
}

type aiOracle struct {
	half                 string // core.SplitInRequest | core.SplitPersistence
	achieved             bool   // did THIS half's oracle succeed (attacker view)?
	inRequestAchieved    bool
	persistenceAchieved  bool
	persistenceDisrupted bool
	neutralized          bool
	triggerAttribution   string
	detectorAbsent       bool
	capabilityPending    bool
	capabilityNote       string
	replaySuccess        int
	replayAttempts       int
	atlas                []string
	owasp                []string
	state                string
	extra                map[string]string
}

// result renders the aiOracle into a core.OracleResult with the standard evidence
// keys populated.
func (o aiOracle) result() core.OracleResult {
	// [P-AUDIT measurement-bug fix] `neutralized` (the strongest MTD-effect: BOTH legs defeated) is
	// DERIVED from the MEASURED outcome — the persistence foothold disrupted AND the in-request leg
	// failed — NOT from arm identity. Several scenarios set `o.neutralized` via
	// `armIsFullPhoenix(env) && X`, which both OVER-credited the reactive arm (claimed NEUTRALIZES
	// even when the in-request payload fired) and UNDER-credited emergent-rate PX (never NEUTRALIZES).
	// Recomputing it here arm-neutrally (consistent with the Condition-2 oracle-honesty scenarios)
	// fixes every aiOracle caller at once; the per-scenario `o.neutralized` field is now informational.
	neutralized := o.persistenceDisrupted && !o.inRequestAchieved
	ev := map[string]string{
		core.EvSplitOracle:          o.half,
		core.EvInRequestAchieved:    b2s(o.inRequestAchieved),
		core.EvPersistenceAchieved:  b2s(o.persistenceAchieved),
		core.EvPersistenceDisrupted: b2s(o.persistenceDisrupted),
		core.EvNeutralized:          b2s(neutralized),
		core.EvTriggerAttribution:   o.triggerAttribution,
		core.EvDetectorAbsent:       b2s(o.detectorAbsent),
		core.EvCapabilityPending:    b2s(o.capabilityPending),
		core.EvCapabilityNote:       o.capabilityNote,
		core.EvReplaySuccess:        itoa(o.replaySuccess),
		core.EvReplayAttempts:       itoa(o.replayAttempts),
		core.EvAtlasIDs:             strings.Join(o.atlas, ","),
		core.EvOwaspIDs:             strings.Join(o.owasp, ","),
	}
	for k, v := range o.extra {
		ev[k] = v
	}
	return core.OracleResult{Achieved: o.achieved, ObservedState: o.state, Evidence: ev}
}

// aiSkip builds a skip-with-note OracleResult for a capability-pending half (kept
// distinct from a defense failure: it carries the capability-pending attribution).
func aiSkip(half, reason string, atlas, owasp []string) core.OracleResult {
	return core.OracleResult{
		Skipped:    true,
		SkipReason: reason,
		Evidence: map[string]string{
			core.EvSplitOracle:        half,
			core.EvTriggerAttribution: core.TriggerCapabilityPending,
			core.EvCapabilityPending:  "true",
			core.EvCapabilityNote:     reason,
			core.EvAtlasIDs:           strings.Join(atlas, ","),
			core.EvOwaspIDs:           strings.Join(owasp, ","),
		},
	}
}

// emitGenuineTrigger drives the genuine matcher path EXACTLY as c2-persistence-evict
// does: if the active defender supports the Emitter (d-fullphoenix), it injects a
// normalized SecurityEvent {Type,ThreatLevel,Source} so matcher.go fires the
// matching action. Returns true if an event was emitted (the matcher path is live).
//
// Event creation is delivery evidence only. A configured defender's supported
// action must be observed separately; this helper never repairs mock substrates.
// eventType is one of amtdv1beta1.TypePanic / TypeTimed (drift is modeled as a
// timed/rotate trigger in the existing AMTD, matching c2-supplychain-foothold's
// regenerate-on-drift semantics).
func emitGenuineTrigger(ctx context.Context, env *core.Env, targetPod, eventType string) bool {
	em, ok := emitterFromEnv(env)
	if !ok {
		return false
	}
	if err := em.EmitSecurityEvent(ctx, env, targetPod, eventType, amtdv1beta1.ThreatLevelHigh); err != nil {
		env.Log.Logf("ai: emit %s trigger error (genuine matcher path): %v", eventType, err)
		return false
	}
	env.Log.Logf("ai: emitted %s SecurityEvent for %s (genuine matcher path)", eventType, targetPod)
	return true
}

// armRotates reports whether the active defender is a rotating arm — i.e. an MTD
// defender that takes rotation/replacement actions, vs the static no-MTD baseline.
//
// [P-REDTEAM measurement-bug fix #1] This used to gate on MeanRotationIntervalSeconds>0,
// which is a FIXED-INTERVAL proxy. That STRUCTURALLY EXCLUDED PX (and any reactive/
// emergent-rate arm), whose rate is a SOLVED decision variable (interval metadata = 0)
// even though it genuinely rotates — so persistence-disruption credit was withheld from
// exactly those arms. The honest test is "does this arm rotate at all": the ONLY arm
// that never rotates is the no-MTD baseline. The ACTUAL per-trial outcome is still gated
// by the measured !persisted in each oracle (the foothold must really be gone), so this
// credits by observed outcome and never over-credits.
func armRotates(env *core.Env) bool {
	return env.DefenderName != "d-nomtd"
}

// armIsFullPhoenix reports whether the active arm is the genuine operator arm.
func armIsFullPhoenix(env *core.Env) bool {
	return env.DefenderName == "d-fullphoenix"
}

// stampRotationTarget returns the label map marking a pod as a rotation target so
// the timer arms + the FullPhoenix AMTD PodSelector churn it.
func stampRotationTarget(extra map[string]string) map[string]string {
	m := map[string]string{defenders.RotationTargetLabel: "true"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func b2s(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// getService fetches a Service in the sandbox namespace (used by oracles that
// check the EXTERNAL endpoint stability under backend-only rotation).
func getService(ctx context.Context, env *core.Env, name string) (*corev1.Service, error) {
	return env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
}

// getOpts is the zero GetOptions, named for brevity in the AI oracles.
func getOpts() metav1.GetOptions { return metav1.GetOptions{} }

// containsMarker reports whether s contains the marker substring.
func containsMarker(s, marker string) bool { return strings.Contains(s, marker) }
