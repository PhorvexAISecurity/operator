package scenarios

import (
	"context"
	"fmt"
	"strings"

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
// stamping, and the ADDITIVE metric evidence are stamped CONSISTENTLY with zero
// core/interface changes. The mocks come from internal/mocks/ai_standins.go.

// aiOracle is the canonical builder for a split-oracle OracleResult. It records
// which half scored, the two halves' outcomes, the MEASURED MTD-effect inputs
// (persistence-disrupted / neutralized), the audit trigger attribution, and the
// AI threat IDs — all into Evidence so the runner lifts them onto the additive
// metric fields without an interface change.
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
	ev := map[string]string{
		core.EvSplitOracle:           o.half,
		core.EvInRequestAchieved:     b2s(o.inRequestAchieved),
		core.EvPersistenceAchieved:   b2s(o.persistenceAchieved),
		core.EvPersistenceDisrupted:  b2s(o.persistenceDisrupted),
		core.EvNeutralized:           b2s(o.neutralized),
		core.EvTriggerAttribution:    o.triggerAttribution,
		core.EvDetectorAbsent:        b2s(o.detectorAbsent),
		core.EvCapabilityPending:     b2s(o.capabilityPending),
		core.EvCapabilityNote:        o.capabilityNote,
		core.EvReplaySuccess:         itoa(o.replaySuccess),
		core.EvReplayAttempts:        itoa(o.replayAttempts),
		core.EvAtlasIDs:              strings.Join(o.atlas, ","),
		core.EvOwaspIDs:              strings.Join(o.owasp, ","),
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
// HARNESS-COMPLETED EFFECT (honesty seam, audit/review #6): this only fires the
// genuine SecurityEvent — the operator then runs its REAL action on the AMTD
// PodSelector-matched pod. For mock AI substrates that are NOT the rotated workload
// (a mock registry digest, an agent-memory store), the SCENARIO completes the
// operator's EFFECT on the mock (e.g. RestoreGolden) GATED ON this returning true —
// i.e. applied ONLY when the genuine matcher path fired, never unconditionally. It
// is a faithful stand-in for the operator's Regenerate/rotate effect on a real GPU
// workload; the seam is disclosed in EFFECTIVENESS-AI.md / ATTACKS-AI.md.
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

// armRotates reports whether the active defender is a rotating arm (non-zero mean
// rotation interval) — used to MEASURE whether a persistence foothold should have
// been bounded by rotation (vs the static d-nomtd baseline).
func armRotates(env *core.Env) bool {
	d, ok := core.LookupDefender(env.DefenderName)
	if !ok {
		return false
	}
	return d.Metadata().MeanRotationIntervalSeconds > 0
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
