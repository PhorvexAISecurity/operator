package scenarios

// ─────────────────────────────────────────────────────────────────────────────
// c2_stealth_foothold.go — a SLIGHTLY-IMPROVED variant of c2-dwell-rotation.
//
// Base attack: plant ONE obvious foothold marker, check it survived.
// This variant: plant a DISGUISED marker (looks like a cache file) + a REDUNDANT
// backup copy in a second location. Succeeds if EITHER survives — so a cleanup
// that only removes the obvious backdoor still fails to evict us. Still type-1
// (R6Covers): a full pod ROTATION wipes both, because both live INSIDE the pod.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"path/filepath"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2StealthFoothold{}) }

// StealthFootholdMarker is our unique persistence marker.
const StealthFootholdMarker = "R6TH-STEALTH-FOOTHOLD"

// The two DISGUISED locations the attacker hides its foothold in (not the obvious
// /tmp/.r6th_backdoor the base attack uses).
const (
	stealthPrimary = "/tmp/.cache/.session_cache" // looks like an app cache file
	stealthBackup  = "/tmp/.config/.sysd"         // redundant copy, looks like config
)

type c2StealthFoothold struct {
	app       string
	targetUID types.UID
}

func (s *c2StealthFoothold) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-stealth-foothold",
		Category:           core.CategoryClassicChain,
		Source:             "improved variant of c2-dwell-rotation: disguised + redundant foothold",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1543.005", "T1564.001"}, // persistence + hide-artifacts
		R6Justification: "A disguised, redundant foothold resists partial cleanup — but both copies live " +
			"inside the pod, so a full rotation still wipes them. Covers (the honest strength).",
	}
}

func (s *c2StealthFoothold) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2sf-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

// Execute — plant the disguised primary + the redundant backup.
func (s *c2StealthFoothold) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	script := stealthPlantCommand(stealthPrimary, stealthBackup)
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", script})
	if err := stimulusExec(ctx, res); err != nil {
		return core.AttackResult{}, err
	}
	s.targetUID = pod.UID
	env.Log.Logf("stealth-foothold plant: %q exit=%d", strings.TrimSpace(res.Stdout), res.ExitCode)
	return core.AttackResult{
		Stages:   []string{"persistence: plant DISGUISED foothold (T1543.005)", "redundancy: plant BACKUP copy (T1564.001)"},
		Commands: []string{"sh -c " + script},
	}, nil
}

// Both writes and their marker reads must succeed before Execute reports that
// the original fake two-copy stimulus was established.
func stealthPlantCommand(primary, backup string) string {
	q := func(path string) string { return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'" }
	return fmt.Sprintf("mkdir -p %s %s && echo %s > %s && echo %s > %s && test \"$(cat %s)\" = %s && test \"$(cat %s)\" = %s && echo planted",
		q(filepath.Dir(primary)), q(filepath.Dir(backup)), StealthFootholdMarker, q(primary), StealthFootholdMarker, q(backup), q(primary), StealthFootholdMarker, q(backup), StealthFootholdMarker)
}

// SuccessOracle — succeeds if EITHER disguised copy is still present after a wait.
func (s *c2StealthFoothold) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	observationPause(8 * time.Second) // give a rotating defender time to act
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		// no running pod = the victim was rotated away = fully evicted
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	check := fmt.Sprintf("for p in %s %s; do if test -f \"$p\"; then cat \"$p\"; else echo %s; fi; done", stealthPrimary, stealthBackup, observationAbsent)
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", check})
	out, err := observationExec(ctx, res)
	if err != nil {
		return core.OracleResult{}, err
	}
	hits := strings.Count(out, StealthFootholdMarker)
	if hits+strings.Count(out, observationAbsent) != 2 {
		return core.OracleResult{}, fmt.Errorf("stealth foothold observation malformed or truncated")
	}
	achieved := hits >= 1
	return core.OracleResult{
		Achieved:      achieved,
		ObservedState: fmt.Sprintf("stealth foothold survived: %d/2 copies present (need >=1)", hits),
		Evidence:      map[string]string{"copiesSurvived": fmt.Sprintf("%d", hits), "observedPod": pod.Name, "originalPodUID": string(s.targetUID), "observedPodUID": string(pod.UID)},
	}, nil
}

func (s *c2StealthFoothold) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
