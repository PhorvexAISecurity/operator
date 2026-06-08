package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai1Pillar03PanicMutation{}) }

// ai1Pillar03PanicMutation: Pillar 03 — a security agent observes model I/O and
// panic-mutates to a clean node on a malicious payload. SPLIT ORACLE:
//   (a) in-request: the malicious payload was processed (model-I/O detector ABSENT,
//       audit #9 -> nothing fires autonomously -> MTD-CANNOT-HELP).
//   (b) response: panic-mutate to a clean node — an INJECTED panic SecurityEvent
//       (the c2-persistence-evict path) NEUTRALIZES (old pod UID gone, replacement
//       Running). A "not neutralized on payload" result is MISSING-TRIGGER (detector
//       absent), NEVER a defense failure. True cross-node relocation is CapMultiNode.
type ai1Pillar03PanicMutation struct {
	infer  *mocks.MockInferenceServer
	oldUID string
}

func (s *ai1Pillar03PanicMutation) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai1-pillar03-panic-mutation",
		Category:           core.CategoryR6Claimed,
		Source:             "R6 Phoenix-for-AI Pillar 03 (panic-mutate to clean node); AUDIT #9 model-I/O ABSENT, #6 NodeRotate",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1059.013", "T1565", "T1610"},
		CapabilityRequirements: []core.Capability{core.CapMultiNode},
		R6Justification:        "The panic-mutation ACTION is BUILT (#4/#6) and fires via an injected panic SecurityEvent — exactly the c2-persistence-evict path. The model-I/O detector is ABSENT (#9) so nothing fires autonomously on a payload (attributed MISSING-TRIGGER). True clean-node relocation MTTR is CapMultiNode-pending. Covers via injected event.",
	}
}

func (s *ai1Pillar03PanicMutation) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	pod, perr := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, infer.PodName, getOpts())
	if perr == nil {
		s.oldUID = string(pod.UID)
	}
	return nil
}

func (s *ai1Pillar03PanicMutation) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Malicious payload processed by the model (marker in model I/O log).
	_ = mocks.MockServerExec(ctx, env, s.infer.MockServer, "echo R6TH-MALICIOUS-PAYLOAD > /tmp/io_log")
	stages := []string{
		"pillar03: malicious payload reaches the model I/O (T1565)",
		"detection: model-I/O detector ABSENT (#9) — no autonomous action",
	}
	cmds := []string{"payload -> /tmp/io_log"}
	// Genuine matcher path: inject a panic so the panic-mutation ACTION fires.
	if emitGenuineTrigger(ctx, env, s.infer.PodName, amtdv1beta1.TypePanic) {
		cmds = append(cmds, "emit panic SecurityEvent -> matcher -> Delete (panic-mutate to clean node)")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai1Pillar03PanicMutation) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// (a) in-request: payload processed (recorded; detector absent so no autonomy).
	inReq := s.infer.MarkerPresent(ctx, env, "/tmp/io_log", "R6TH-MALICIOUS-PAYLOAD")

	// (b) response: after the injected panic window, the old inference pod UID is
	// gone and a replacement is Running (panic-mutation neutralized the foothold).
	time.Sleep(6 * time.Second)
	oldGone := true
	if cur, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.infer.PodName, getOpts()); err == nil {
		if string(cur.UID) == s.oldUID && cur.DeletionTimestamp == nil {
			oldGone = false
		}
	}
	neutralized := armIsFullPhoenix(env) && oldGone
	disrupted := (armRotates(env) || armIsFullPhoenix(env)) && oldGone

	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             !oldGone, // attacker keeps the foothold iff the old pod persists
		inRequestAchieved:    inReq,
		persistenceAchieved:  !oldGone,
		persistenceDisrupted: disrupted,
		neutralized:          neutralized,
		triggerAttribution:   core.TriggerHarnessInjected, // panic action proven via injected event
		detectorAbsent:       true,                        // model-I/O detector absent for autonomy
		capabilityPending:    true,
		capabilityNote:       "true cross-node relocation MTTR is CapMultiNode-pending; single-node action path proven via injected panic",
		atlas:                []string{"AML.T0051", "AML.T0020", "AML.T0031"},
		owasp:                []string{"LLM01:2025", "LLM05:2025"},
		state:                fmt.Sprintf("payload processed=%v; old inference pod replaced=%v (panic-mutation action via injected event; relocation pending)", inReq, oldGone),
	}
	return o.result(), nil
}

func (s *ai1Pillar03PanicMutation) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
