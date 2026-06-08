package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2AgentInjectionToPersistence{}) }

// ai2AgentInjectionToPersistence: injection escalating to durable persistence (a
// kill-chain bridge). SPLIT ORACLE: (a) injection lands a persistence step (no
// semantic filter -> CANNOT-HELP); (b) persistence established — an INJECTED panic/
// policy-violation SecurityEvent -> Delete (the c2-persistence-evict path) evicts
// the agent pod foothold (marker gone, old UID replaced) -> MTD-NEUTRALIZES.
type ai2AgentInjectionToPersistence struct {
	agent  *mocks.MockAgentRuntime
	oldUID string
}

func (s *ai2AgentInjectionToPersistence) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-agent-injection-to-persistence",
		Category:           core.CategoryR6Claimed,
		Source:             "Agentic: injection escalating to durable persistence (kill-chain bridge)",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1059.013", "T1543.005"},
		R6Justification:    "Injection itself is not preventable (no semantic filter). But an injected panic/policy-violation -> Delete (the c2-persistence-evict path, BUILT) evicts the planted agent foothold. Covers via injected event.",
	}
}

func (s *ai2AgentInjectionToPersistence) Setup(ctx context.Context, env *core.Env) error {
	agent, err := mocks.DeployMockAgentRuntime(ctx, env)
	if err != nil {
		return err
	}
	s.agent = agent
	if pod, perr := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, agent.PodName, getOpts()); perr == nil {
		s.oldUID = string(pod.UID)
	}
	return nil
}

func (s *ai2AgentInjectionToPersistence) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.agent.PlantBackdoorStep(ctx, env) // injection plants a persistence backdoor
	stages := []string{
		"injection: agent injection executes a persistence step (T1059.013)",
		"persistence: agent backdoor planted (T1543.005)",
	}
	cmds := []string{"agent backdoor -> " + mocks.AgentBackdoorMarker}
	if emitGenuineTrigger(ctx, env, s.agent.PodName, amtdv1beta1.TypePanic) {
		cmds = append(cmds, "emit panic SecurityEvent -> matcher -> Delete (evict agent foothold)")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2AgentInjectionToPersistence) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.agent.BackdoorPresent(ctx, env)
	time.Sleep(6 * time.Second)
	stillThere := s.agent.BackdoorPresent(ctx, env)
	oldGone := true
	if cur, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.agent.PodName, getOpts()); err == nil {
		if string(cur.UID) == s.oldUID && cur.DeletionTimestamp == nil {
			oldGone = false
		}
	}
	neutralized := armIsFullPhoenix(env) && !stillThere && oldGone
	disrupted := (armRotates(env) || armIsFullPhoenix(env)) && !stillThere
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             stillThere,
		inRequestAchieved:    inReq,
		persistenceAchieved:  stillThere,
		persistenceDisrupted: disrupted,
		neutralized:          neutralized,
		triggerAttribution:   core.TriggerHarnessInjected,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0051", "AML.T0054", "AML.T0061"},
		owasp:                []string{"LLM01:2025", "LLM06:2025"},
		state:                fmt.Sprintf("injection planted persistence=%v; backdoor evicted (gone=%v, old UID replaced=%v)", inReq, !stillThere, oldGone),
	}
	return o.result(), nil
}

func (s *ai2AgentInjectionToPersistence) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-agent")
}
