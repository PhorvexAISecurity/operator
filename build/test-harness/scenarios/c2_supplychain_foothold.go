package scenarios

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c2SupplyChainFoothold{}) }

// c2SupplyChainFoothold: a foothold established by a malicious-image container.
// ORACLE (attacker): the malicious-image marker process survives PAST the
// rotation interval. Disruption = foothold replaced by a known-good image within
// the interval. NOTE: prevention of the initial pull is NOT claimed/measured here
// (that is c3-supplychain). R6 partial: rotation caps the foothold's lifetime but
// does not block the pull/exec.
type c2SupplyChainFoothold struct {
	app       string
	targetUID types.UID
}

func (s *c2SupplyChainFoothold) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-supplychain-foothold",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; AMTD-AI-infra SolarWinds; MAESTRO L4 compromised images",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1525", "T1204.003", "T1610", "T1543.005"},
		R6Justification:    "The CRD Baseline/Regenerate path is digest-pin REFERENCES + a TYPE-ONLY Regenerate action (no live signature/provenance enforcement). Rotation bounds the foothold's lifetime but does NOT block the malicious image running. Caps dwell, not the pull/exec. Partial.",
	}
}

func (s *c2SupplyChainFoothold) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2sc-target"
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	// Deploy a rotation-target pod whose entrypoint emulates a POISONED image
	// (writes the tampered marker) — the foothold from a malicious image.
	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": s.app}, nil)
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("app", mocks.PoisonedImageCommand("/tmp/.r6th_foothold"), 100, 32).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # malicious-image foothold stand-in", s.app, mocks.BusyboxImage, env.Config.Namespace))
	_, err := createFreshPod(ctx, env, pod, "malicious-image foothold stand-in")
	return err
}

func (s *c2SupplyChainFoothold) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.targetUID = pod.UID
	stages := []string{
		"supply-chain: malicious image pulled+run (T1204.003/T1525)",
		"foothold: injected layer's payload executes (marker written)",
	}
	// Confirm the foothold payload ran.
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", "cat /tmp/.r6th_foothold 2>/dev/null"})
	if err := stimulusExec(ctx, res); err != nil {
		return core.AttackResult{}, err
	}
	if !strings.Contains(res.Stdout, mocks.TamperedMarker) {
		return core.AttackResult{}, fmt.Errorf("foothold marker not established")
	}
	env.Log.Logf("c2-supplychain-foothold: foothold marker=%q", strings.TrimSpace(res.Stdout))
	return core.AttackResult{Stages: stages, Commands: []string{"image entrypoint wrote " + mocks.TamperedMarker}}, nil
}

func (s *c2SupplyChainFoothold) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Wait past the rotation interval; check whether the foothold marker survives.
	observationPause(8 * time.Second)
	ev := map[string]string{}
	ev["originalPodUID"] = string(s.targetUID)
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		// A non-target replacement / removal means the foothold image is gone.
		ev["footholdAlive"] = "false"
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	res := env.Exec(ctx, pod.Name, firstContainer(pod), markerReadCommand("/tmp/.r6th_foothold"))
	alive, err := observedMarker(ctx, res, mocks.TamperedMarker)
	if err != nil {
		return core.OracleResult{}, err
	}
	ev["footholdAlive"] = fmt.Sprintf("%v", alive)
	ev["observedPod"] = pod.Name
	ev["observedPodUID"] = string(pod.UID)
	// NOTE: because a rotation REPLACEMENT re-runs the SAME poisoned image
	// entrypoint (the marker re-appears), the foothold marker can survive a blind
	// rotation — faithfully showing rotation caps DWELL but not the poisoned pull.
	state := fmt.Sprintf("malicious-image foothold marker present after interval=%v in %s", alive, pod.Name)
	return core.OracleResult{Achieved: alive, ObservedState: state, Evidence: ev}, nil
}

func (s *c2SupplyChainFoothold) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
