package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2ReconWindow{}) }

// c2ReconWindow: recon-window denial. Attacker maps a target pod's IP+identity at
// t0, then re-validates the SAME endpoint after one interval. ORACLE (attacker):
// the previously-mapped IP/identity is STILL valid after the window. Recon
// "denied" iff the mapped endpoint is no longer valid (rotated). R6 partial:
// rotation denies a STABLE map, not the recon itself.
type c2ReconWindow struct {
	app   string
	mapIP  string
	mapUID string
}

func (s *c2ReconWindow) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-recon-window",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; Phoenix-K8s Network Obfuscation/Discovery prevention; ADA minimax",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1613", "T1046", "T1069", "T1526"},
		R6Justification:    "Rotation makes a recon snapshot go stale at the interval boundary (denies a STABLE map) but one full recon completes within an interval and Phoenix emits no recon detection. Denies persistence-of-recon, not recon itself. Partial.",
	}
}

func (s *c2ReconWindow) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2rw-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c2ReconWindow) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	// Snapshot the endpoint identity at t0 (the recon map).
	s.mapIP = pod.Status.PodIP
	s.mapUID = string(pod.UID)
	stages := []string{
		"discovery: enumerate target pod IP+identity at t0 (T1046/T1613)",
		"map: record the endpoint for later use",
	}
	env.Log.Logf("c2-recon-window: mapped %s -> ip=%s uid=%s", pod.Name, s.mapIP, s.mapUID)
	return core.AttackResult{Stages: stages, Commands: []string{"kubectl get pod -o wide  # snapshot ip/identity"}, Notes: map[string]string{"ip": s.mapIP, "uid": s.mapUID}}, nil
}

func (s *c2ReconWindow) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Re-validate after one interval window.
	time.Sleep(8 * time.Second)
	stillValid := false
	cur, err := runningPodByApp(ctx, env, s.app)
	if err == nil {
		// The mapped identity is still valid iff the SAME UID + IP persist.
		if string(cur.UID) == s.mapUID && cur.Status.PodIP == s.mapIP {
			stillValid = true
		}
	}
	ev := map[string]string{
		"mappedIP":   s.mapIP,
		"mappedUID":  s.mapUID,
		"stillValid": fmt.Sprintf("%v", stillValid),
	}
	// Attacker "achieves" iff the recon map is still valid (no rotation invalidated it).
	achieved := stillValid
	state := fmt.Sprintf("recon map (ip=%s uid=%s) still valid after interval=%v", s.mapIP, s.mapUID, stillValid)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c2ReconWindow) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
