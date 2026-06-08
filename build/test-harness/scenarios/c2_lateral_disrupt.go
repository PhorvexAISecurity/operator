package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2LateralDisrupt{}) }

// c2LateralDisrupt: the "lateral movement becomes impossible" product CLAIM,
// measured honestly. Attacker mid-lateral-move (A -> B) is disrupted iff the
// in-flight session breaks AND the command in B fails to complete because A or B
// was rotated during the move. ORACLE (attacker): command runs in B before any
// rotation. R6 partial (overshoots: no NetworkPolicy actuator in api/v1beta1;
// disruption is only the side effect of rotating the moving pod).
type c2LateralDisrupt struct {
	srcApp string
	dstApp string
}

const c2LatMarker = "R6TH-C2-LATERAL-DONE"

func (s *c2LateralDisrupt) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-lateral-disrupt",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; Phoenix-K8s Temporal Network Policies 'lateral movement impossible'; ADA 3.3",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1550.001", "T1046", "T1609", "T1021"},
		R6Justification:    "api/v1beta1 has NO NetworkPolicy/service-mesh actuator and no lateral emitter; the 'Temporal Network Policies' bullet is not wired. Lateral movement is disrupted only by rotating the moving pod, opportunistically. The strong product claim overshoots the implemented capability. Partial.",
	}
}

func (s *c2LateralDisrupt) Setup(ctx context.Context, env *core.Env) error {
	s.srcApp = "c2lat-src"
	s.dstApp = "c2lat-dst"
	if _, err := deployTarget(ctx, env, s.srcApp, "", nil); err != nil {
		return err
	}
	if _, err := deployTarget(ctx, env, s.dstApp, "", nil); err != nil {
		return err
	}
	return nil
}

func (s *c2LateralDisrupt) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	src, err := runningPodByApp(ctx, env, s.srcApp)
	if err != nil {
		return core.AttackResult{}, err
	}
	dst, err := runningPodByApp(ctx, env, s.dstApp)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"lateral-move: begin reaching pod B from compromised pod A (T1021)",
		"in-flight: drive a multi-step command in B (rotation may sever it)",
	}
	// A slow, multi-step "in-flight" command in B: sleep then write the marker, so
	// a rotation landing mid-move severs it before the marker is written.
	dialCmd := fmt.Sprintf("nc -w 1 %s 1234 2>/dev/null; echo reached-B", dst.Status.PodIP)
	_ = env.Exec(ctx, src.Name, firstContainer(src), []string{"sh", "-c", dialCmd})
	slowCmd := "sleep 4; echo " + c2LatMarker + " > /tmp/.r6th_c2lat"
	res := env.Exec(ctx, dst.Name, firstContainerName(dst.Name, env), []string{"sh", "-c", slowCmd})
	env.Log.Logf("c2-lateral-disrupt: in-flight command exit=%d", res.ExitCode)
	return core.AttackResult{Stages: stages, Commands: []string{"sh -c '" + dialCmd + "'", "sh -c '" + slowCmd + "'"}}, nil
}

func (s *c2LateralDisrupt) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(2 * time.Second)
	ev := map[string]string{}
	dst, err := runningPodByApp(ctx, env, s.dstApp)
	if err != nil {
		return core.OracleResult{Achieved: false, ObservedState: "pod B rotated/absent — in-flight move severed", Evidence: ev}, nil
	}
	res := env.Exec(ctx, dst.Name, firstContainerName(dst.Name, env), []string{"sh", "-c", "cat /tmp/.r6th_c2lat 2>/dev/null"})
	done := strings.Contains(res.Stdout, c2LatMarker)
	ev["commandCompletedInB"] = fmt.Sprintf("%v", done)
	ev["podB"] = dst.Name
	state := fmt.Sprintf("in-flight command completed in B before rotation=%v", done)
	return core.OracleResult{Achieved: done, ObservedState: state, Evidence: ev}, nil
}

func (s *c2LateralDisrupt) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.srcApp, s.dstApp)
}
