package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// apt_actuation_live.go (P-REDTEAM end-to-end) — drives the RL adversary's two discovered attacks
// (the λ-pump and the dispersion-steer) through the FULL LIVE loop: the real Phorvex brain DECIDES,
// EMITS a SecurityEvent, the extended-Phoenix actuator runs it, and the foothold pod ACTUALLY
// changes (rotate/delete) in the live cluster. The oracle confirms the REAL change from the cluster
// (the foothold pod's UID is gone == replaced, the backdoor marker absent) — not the decision math.
//
//   - apt-lambda-pump-live:      foothold + a FLOOD of cheap decoys (the λ-pump: inflate budget
//     demand to pump the shadow-price and starve the real rotation). The shipped λ-fix bounds λ, so
//     the foothold is still rotated.
//   - apt-dispersion-steer-live: foothold + a few HIGH-value (data-class=restricted) FRESH decoys
//     (the dispersion-steer: out-net the foothold for the B=1 slot). The shipped provenance fix
//     discounts the fresh decoys, so the genuinely-due foothold is still selected + rotated.
//
// Run against d-phorvex (SHIPPED, fixed) => the foothold IS rotated despite the decoys (the fixes
// hold end-to-end). Against d-nomtd => the foothold survives (the anchor). The pre-fix suppression
// is shown by the d-phorvex-vuln-steer arm (proactiveFloor=0 disables the provenance discount).
type aptActuationLive struct {
	id         string
	decoyCount int
	decoyClass string // restricted (high asset value => steer) | internal (modest => λ-pump flood)
	ttps       []string
	app        string
	decoys     []string
	oldUID     string
}

func (s *aptActuationLive) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               s.id,
		Category:           core.CategoryR6Claimed,
		Source:             "P-REDTEAM live actuation proof: RL-discovered decoy crowd-out (" + s.decoyClass + ")",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: s.ttps,
		R6Justification:    "End-to-end proof that the Phorvex decide->emit->actuate loop survives the RL's decoy crowd-out: under the shipped fixes the real foothold pod is actually rotated (UID replaced) despite the decoys; pre-fix the decoys suppress the actuation.",
	}
}

func (s *aptActuationLive) Setup(ctx context.Context, env *core.Env) error {
	s.app = s.id + "-fh"
	// the foothold is a genuine, modest-value rotation target; it ages while the operators build +
	// lease, so by the first decision tick its exposure >= proactiveFloor (prov=1, genuinely due).
	pod, err := deployTarget(ctx, env, s.app, "", map[string]string{"data-class": "internal"})
	if err != nil {
		return err
	}
	s.oldUID = string(pod.UID)
	return nil
}

func (s *aptActuationLive) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.oldUID = string(pod.UID)
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))

	// spawn the FRESH decoys (the attack): rotation-target candidates with manufactured coverage that
	// (pre-fix) out-net / starve the real foothold for the single move budget.
	s.decoys = nil
	for i := 0; i < s.decoyCount; i++ {
		dn := fmt.Sprintf("%s-dec-%d", s.id, i)
		if _, derr := deployTarget(ctx, env, dn, "", map[string]string{"data-class": s.decoyClass}); derr != nil {
			env.Log.Logf("%s: decoy %s deploy error: %v", s.id, dn, derr)
			continue
		}
		s.decoys = append(s.decoys, dn)
	}
	stages := []string{
		"persistence: plant foothold backdoor (T1543.005)",
		fmt.Sprintf("evasion: spawn %d fresh %s decoys to crowd the foothold out of the rotation budget (the RL-discovered crowd-out)", len(s.decoys), s.decoyClass),
		"objective: keep the genuinely-due foothold from being SELECTED/rotated (suppress the actuation)",
	}
	cmds = append(cmds, fmt.Sprintf("spawn %d decoys (data-class=%s) as rotation-target candidates", len(s.decoys), s.decoyClass))
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{
		"footholdUID": s.oldUID, "decoyCount": fmt.Sprintf("%d", len(s.decoys)), "decoyClass": s.decoyClass,
	}}, nil
}

func (s *aptActuationLive) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// give the live decide->emit->actuate loop a window (several Phorvex ticks @ base-interval 4s).
	time.Sleep(16 * time.Second)

	alive, obsPod := backdoorAliveWrap(ctx, env, s.app)
	// the REAL change: the foothold pod's UID is gone (replaced), confirmed from the LIVE cluster.
	footholdRotated := true
	if cur, err := runningPodByApp(ctx, env, s.app); err == nil {
		if string(cur.UID) == s.oldUID {
			footholdRotated = false
		}
	}
	ev := map[string]string{
		"footholdOldUID":  s.oldUID,
		"footholdRotated": fmt.Sprintf("%v", footholdRotated), // the live K8s change actually happened
		"backdoorAlive":   fmt.Sprintf("%v", alive),
		"decoyCount":      fmt.Sprintf("%d", len(s.decoys)),
		"decoyClass":      s.decoyClass,
		"observedPod":     obsPod,
		"auditHint":       "grep the d-phorvex raw log / --audit-json for selected:true,actuated:true,pod=" + s.app,
	}
	// the attacker ACHIEVES iff the foothold survived (the decoys suppressed the actuation). A
	// successful real rotation => backdoor gone + UID replaced => disruption => achieved=false.
	achieved := alive && !footholdRotated
	state := fmt.Sprintf("live actuation: footholdRotated=%v backdoorAlive=%v under %d %s decoys", footholdRotated, alive, len(s.decoys), s.decoyClass)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *aptActuationLive) Teardown(ctx context.Context, env *core.Env) error {
	apps := append([]string{s.app}, s.decoys...)
	return teardownByApp(ctx, env, apps...)
}

func init() {
	core.RegisterScenario(&aptActuationLive{
		id: "apt-lambda-pump-live", decoyCount: 8, decoyClass: "internal",
		ttps: []string{"T1496", "T1499.004", "T1078.004", "T1611"},
	})
	core.RegisterScenario(&aptActuationLive{
		id: "apt-dispersion-steer-live", decoyCount: 3, decoyClass: "restricted",
		ttps: []string{"T1036.005", "T1078.004", "T1498.001", "T1611"},
	})
}
