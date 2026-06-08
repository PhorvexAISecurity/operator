package scenarios

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() {
	core.RegisterScenario(&bReconLifetime{})
	core.RegisterScenario(&bReconLifetimeAI{})
}

// measureReconLifetime polls (500ms) the at-risk pod's IDENTITY (UID) from the moment the
// attacker captures its reconnaissance snapshot, and returns the wall-seconds that snapshot
// stays VALID + USABLE — i.e. until the FIRST identity change (the original UID is gone /
// replaced by a fresh-identity pod). This is the detector-INDEPENDENT recon-validity
// mechanism (test B): a move that gives the at-risk asset a NEW identity invalidates the
// attacker's map regardless of any detector. It is DISTINCT from foothold-survival in that
// it keys on identity stability, not the backdoor marker. Returns (lifetimeSec, stillValid).
func measureReconLifetime(ctx context.Context, env *core.Env, appLabel, origUID string, maxWindow time.Duration) (float64, bool) {
	start := time.Now()
	deadline := start.Add(maxWindow)
	for {
		valid := false
		if pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + appLabel}); err == nil {
			for i := range pods.Items {
				p := &pods.Items[i]
				if string(p.UID) == origUID && p.DeletionTimestamp == nil {
					valid = true // the originally-mapped identity is still live = recon usable
					break
				}
			}
		}
		if !valid {
			return time.Since(start).Seconds(), false // identity changed/gone => recon invalidated
		}
		if time.Now().After(deadline) {
			return time.Since(start).Seconds(), true // recon stayed valid the whole window
		}
		select {
		case <-ctx.Done():
			return time.Since(start).Seconds(), true
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// bReconLifetime is P3-DEEP Test B (K8s): the recon-validity-lifetime mechanism. The
// attacker maps the at-risk pod's identity (UID/IP/placement); the metric is how long that
// recon stays valid. PX invalidates it on rising exposure (short, MEASURED with a CI — NOT
// "by construction": the proactive floor is a soft belief term, eviction is the greedy's
// probabilistic outcome under budget). A learnable fixed-cadence blind keeps recon valid to
// ~its interval (the attacker strikes in the lull); a static arm keeps it valid for the
// whole window.
type bReconLifetime struct {
	app     string
	origUID string
}

func (s *bReconLifetime) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "b-recon-lifetime",
		Category:           core.CategoryClassicChain,
		Source:             "P3-DEEP Test B; the detector-independent recon-validity mechanism (PRD §4 re-recon cost)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1590", "T1592", "T1078"},
		R6Justification:    "Measures how long the attacker's identity-recon stays usable. A move that re-identities the asset invalidates it WITHOUT a detector. Blind keeps recon valid to ~its (learnable) interval; PX invalidates on rising exposure. Partial: blind also re-identities on its schedule.",
	}
}

func (s *bReconLifetime) Setup(ctx context.Context, env *core.Env) error {
	s.app = "b-recon"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *bReconLifetime) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.origUID = string(pod.UID)
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	return core.AttackResult{
		Stages:   []string{"map the at-risk pod identity (UID/IP/placement) = the reconnaissance snapshot (T1590/T1592)", "the recon stays usable until the asset is re-identified"},
		Commands: cmds,
	}, nil
}

func (s *bReconLifetime) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	life, stillValid := measureReconLifetime(ctx, env, s.app, s.origUID, 20*time.Second)
	ev := map[string]string{
		"reconValidLifetimeSeconds": fmt.Sprintf("%.1f", life),
		core.EvReactionSeconds:      fmt.Sprintf("%.1f", life),
	}
	state := fmt.Sprintf("recon-validity: identity %s stayed usable %.1fs [recon-valid=%.1fs] [recon-invalidated=%v] [recon-lifetime=true]",
		s.origUID[:8], life, life, !stillValid)
	return core.OracleResult{Achieved: stillValid, ObservedState: state, Evidence: ev}, nil
}

func (s *bReconLifetime) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}

// bReconLifetimeAI is Test B for the AI product. On kind only the BACKEND POD-IDENTITY
// PROXY is measurable; the real AI recon (model-fingerprint / inference endpoint / GPU
// co-location) and its invalidation (model-swap / route-rotate / MIG-rebind) are Phase-2 /
// GPU-bound = [SP-0-PENDING]. HONEST: the external endpoint is STABLE for ALL arms incl PX
// on kind, so the AI recon-lifetime on the real surface TIES across arms — we report the
// proxy + shape now and carry the native magnitude as capability-pending; never fabricated.
type bReconLifetimeAI struct {
	app     string
	origUID string
}

func (s *bReconLifetimeAI) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "b-recon-lifetime-ai",
		Category:           core.CategoryR6Claimed,
		Source:             "P3-DEEP Test B (AI); model-fingerprint/endpoint/GPU-co-location recon (PRD §3.B)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1590", "T1530", "T1078.004"},
		R6Justification:    "AI recon-validity (model-fingerprint/endpoint/co-location). On kind only the backend pod-identity proxy is measurable; native fingerprint/MIG-rebind invalidation is GPU-bound [SP-0-PENDING]. The external endpoint is stable for all arms incl PX -> ties on the real surface; reported honestly.",
	}
}

func (s *bReconLifetimeAI) Setup(ctx context.Context, env *core.Env) error {
	s.app = "b-recon-ai"
	_, err := deployTarget(ctx, env, s.app, "", map[string]string{"workload": "nim", "data-class": "restricted"})
	return err
}

func (s *bReconLifetimeAI) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.origUID = string(pod.UID)
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	return core.AttackResult{
		Stages:   []string{"map the NIM backend identity + (real surface) model-fingerprint/endpoint/GPU-co-location", "AI recon-validity proxy on kind; native fingerprint invalidation [SP-0-PENDING]"},
		Commands: cmds,
		Notes:    map[string]string{"aiSurface": "model-fingerprint/endpoint/gpu-co-location", "nativeMagnitude": "SP-0-PENDING"},
	}, nil
}

func (s *bReconLifetimeAI) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	life, stillValid := measureReconLifetime(ctx, env, s.app, s.origUID, 20*time.Second)
	ev := map[string]string{
		"reconValidLifetimeSeconds": fmt.Sprintf("%.1f", life),
		core.EvCapabilityPending:    "true",
		core.EvCapabilityNote:       "ai-recon-native-gpu (fingerprint/MIG invalidation)",
		core.EvReactionSeconds:      fmt.Sprintf("%.1f", life),
	}
	state := fmt.Sprintf("AI recon-validity (backend-identity PROXY) %.1fs [recon-valid=%.1fs] [recon-invalidated=%v] [recon-lifetime=true] [ai=true] [native-fingerprint=SP-0-PENDING]",
		life, life, !stillValid)
	return core.OracleResult{Achieved: stillValid, ObservedState: state, Evidence: ev}, nil
}

func (s *bReconLifetimeAI) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
