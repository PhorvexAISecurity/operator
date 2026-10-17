package decision

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestVoiceMemoryObservedNoteEntersNormalDecisionWithAlternatives(t *testing.T) {
	creator := "system:serviceaccount:phorvex-system:console"
	pod := model.Pod{Namespace: "voice", Name: "bot-1", UID: "55555555-5555-4555-8555-555555555555", Ready: true, ReadyReplicas: 1, StartedAt: time.Now().Add(-2 * time.Hour),
		VoiceMemoryConfigMap: "voice-memory-policy", VoiceMemoryDeploymentUID: "11111111-1111-4111-8111-111111111111",
		VoiceMemorySourceSHA256: strings.Repeat("a", 64), VoiceMemoryEventCreator: creator}
	pod.VoiceMemoryObservation = &model.VoiceMemoryObservation{EventName: "observed", EventUID: "66666666-6666-4666-8666-666666666666", CreatorIdentity: creator,
		ScenarioID: "ai2-agent-memory-contamination", CaseID: "owned-note", TargetPodUID: pod.UID, DeploymentUID: pod.VoiceMemoryDeploymentUID,
		ConfigMapUID: "44444444-4444-4444-8444-444444444444", RuleSHA256: strings.Repeat("b", 64), SourceSHA256: pod.VoiceMemorySourceSHA256,
		CallerID: "+15551234567", NoteSHA256: strings.Repeat("c", 64), PolicyName: "voice-defense", PolicyUID: "33333333-3333-4333-8333-333333333333", PolicyGeneration: 1}
	v := &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm,
		Events: []model.SecurityEventInfo{{Name: pod.VoiceMemoryObservation.EventName, UID: pod.VoiceMemoryObservation.EventUID,
			Type: model.AttackVectorVoiceMemory, ThreatLevel: "critical", Source: "redteam", Trust: "trusted", CreatorIdentity: creator,
			TargetsPod: true, ConsoleTargetPodUID: pod.UID, Age: 5 * time.Second, CreatedAt: time.Now().Add(-5 * time.Second), AnomalyScore: .95}}}
	pol := model.Policy{Tenant: "voice", Namespace: "voice", PolicyName: "voice-defense", PolicyUID: pod.VoiceMemoryObservation.PolicyUID, PolicyGeneration: 1,
		Mode: "active", TraceEnabled: true, MaxMovesPerTick: 1, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, Lambda: .4,
		CostCeiling: model.DefaultCostCeiling, MinAvailableReplicas: 1, ProactiveFloor: 15 * time.Minute, ExposurePressureScale: 15 * time.Minute,
		AntiOverRotationWindow: 90 * time.Second, TickInterval: 10 * time.Second, EventAgeHorizon: time.Hour, EventDriven: true, ReactiveOnly: true,
		AssetWeights:   model.AssetLabelWeights{Default: .4},
		EnabledActions: map[model.Action]bool{model.ActionVoiceMemoryNoteRevoke: true, model.ActionRotate: true, model.ActionQuarantine: true}}
	clock := exposure.NewClock()
	now := time.Now()
	clock.Observe(exposure.Observation{Owner: pol.Owner(), Namespace: pod.Namespace, Pod: pod.Name, StartedAt: pod.StartedAt, Fingerprints: model.ExposureFingerprints(pod)}, now)
	v.ExposureByVariable = clock.Since(pol.Owner(), pod.Namespace, pod.Name, now)
	engine := NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW recon profile absent")
	}
	engine.Recon = profile
	set, _ := engine.AssembleSet([]*model.WorkloadView{v}, pol)
	seen := map[model.Action]bool{}
	for _, c := range set.Candidates {
		seen[c.Action] = true
	}
	for _, e := range set.Excluded {
		seen[e.Action] = true
	}
	if !seen[model.ActionVoiceMemoryNoteRevoke] || !seen[model.ActionRotate] || !seen[model.ActionQuarantine] {
		t.Fatalf("normal policy alternatives absent: candidates=%+v excluded=%+v", set.Candidates, set.Excluded)
	}
	foundCover := false
	for _, c := range set.Candidates {
		if c.Action == model.ActionVoiceMemoryNoteRevoke && len(c.CoverKeys) > 0 {
			foundCover = true
		}
	}
	if !foundCover {
		t.Fatalf("exact Voice observation gave no action-specific cover: %+v", set)
	}
	decisions := engine.Decide([]*model.WorkloadView{v}, pol)
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("normal Voice decision absent: %+v", decisions)
	}
	if !decisions[0].Selected || decisions[0].Action != model.ActionVoiceMemoryNoteRevoke {
		t.Fatalf("normal active policy did not select exact Voice memory action: %+v", decisions[0])
	}
	if decisions[0].VoiceMemoryObservation == nil || decisions[0].VoiceMemoryObservation.EventUID != pod.VoiceMemoryObservation.EventUID {
		t.Fatalf("Voice decision lost observed event identity: %+v", decisions[0])
	}
	pol.PolicyUID = "77777777-7777-4777-8777-777777777777"
	wrong, _ := engine.AssembleSet([]*model.WorkloadView{v}, pol)
	for _, c := range wrong.Candidates {
		if c.Action == model.ActionVoiceMemoryNoteRevoke {
			t.Fatal("wrong selecting policy kept Voice candidate")
		}
	}
}
