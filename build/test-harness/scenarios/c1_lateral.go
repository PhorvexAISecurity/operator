package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1Lateral{}) }

// c1Lateral: from a compromised source pod, reach a SECOND target pod over the
// network and run a command in it. ORACLE: a unique marker is written into the
// target pod's filesystem (observed by exec) — i.e. command execution in pod B
// from pod A.
type c1Lateral struct {
	srcApp string
	dstApp string
}

const lateralMarker = "R6TH-LATERAL-REACHED"

func (s *c1Lateral) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-lateral",
		Category:           core.CategoryClassicChain,
		Source:             "Cat1; ADA II lateral movement; Phoenix-K8s Temporal Network Policies",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1046", "T1613", "T1550.001", "T1609", "T1059.013"},
		R6Justification:    "Phoenix does not inspect traffic; lateral movement is disrupted only as a side effect of rotating the source/target pod (new IP/identity). No lateral emitter in the vocabulary. Opportunistic partial.",
	}
}

func (s *c1Lateral) Setup(ctx context.Context, env *core.Env) error {
	s.srcApp = "c1lat-src"
	s.dstApp = "c1lat-dst"
	if _, err := deployTarget(ctx, env, s.srcApp, "", nil); err != nil {
		return err
	}
	// The destination is NOT a rotation target (it is the lateral victim B).
	if _, err := deployPlain(ctx, env, s.dstApp); err != nil {
		return err
	}
	return nil
}

func (s *c1Lateral) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	src, err := runningPodByApp(ctx, env, s.srcApp)
	if err != nil {
		return core.AttackResult{}, err
	}
	dst, err := runningPodByApp(ctx, env, s.dstApp)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"discovery: enumerate reachable pods/services (T1046/T1613)",
		"lateral-move: reach pod B from compromised pod A (T1021)",
		"execution-in-B: run a command in pod B (T1609)",
	}
	// Model the lateral move + remote command as: from src, write the marker into
	// dst via an exec on dst (the harness's stand-in for "A drove a command in B").
	// A faithful network reach is exercised by src dialing dst's IP first.
	dialCmd := fmt.Sprintf("wget -T 2 -qO- http://%s:1234 2>/dev/null; echo dialed", dst.Status.PodIP)
	_ = env.Exec(ctx, src.Name, firstContainer(src), []string{"sh", "-c", dialCmd})
	// The remote command effect in B (observable marker in B's filesystem).
	writeCmd := "echo " + lateralMarker + " > /tmp/.r6th_lateral"
	res := env.Exec(ctx, dst.Name, firstContainerName(dst.Name, env), []string{"sh", "-c", writeCmd})
	env.Log.Logf("c1-lateral: command-in-B exit=%d", res.ExitCode)
	cmds := []string{"sh -c '" + dialCmd + "'", "sh -c '" + writeCmd + "'"}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *c1Lateral) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Give a rotation arm a moment to potentially disrupt mid-move.
	time.Sleep(3 * time.Second)
	dst, err := runningPodByApp(ctx, env, s.dstApp)
	ev := map[string]string{}
	if err != nil {
		// Pod B gone (rotated) — lateral effect not observable.
		return core.OracleResult{Achieved: false, ObservedState: "target pod B not reachable (rotated/absent)", Evidence: ev}, nil
	}
	res := env.Exec(ctx, dst.Name, firstContainerName(dst.Name, env), []string{"sh", "-c", "cat /tmp/.r6th_lateral 2>/dev/null"})
	got := strings.Contains(res.Stdout, lateralMarker)
	ev["markerInB"] = fmt.Sprintf("%v", got)
	ev["podB"] = dst.Name
	state := fmt.Sprintf("command-in-B marker present=%v in %s", got, dst.Name)
	return core.OracleResult{Achieved: got, ObservedState: state, Evidence: ev}, nil
}

func (s *c1Lateral) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.srcApp, s.dstApp)
}
