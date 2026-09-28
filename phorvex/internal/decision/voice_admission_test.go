package decision

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

func TestVoiceAdmissionObservedAccessEntersNormalDecisionWithAlternatives(t *testing.T) {
	pod := boundVoiceAdmissionView().Pod
	pod.Ready = true
	pod.ReadyReplicas = 1
	pod.StartedAt = time.Now().Add(-2 * time.Hour)
	creator := voiceadmissionpolicy.Creator
	v := &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm,
		Events: []model.SecurityEventInfo{{Name: pod.VoiceAdmissionObservation.EventName, UID: pod.VoiceAdmissionObservation.EventUID,
			Type: model.AttackVectorVoiceAdmission, ThreatLevel: "critical", Source: "redteam", Trust: "trusted", CreatorIdentity: creator,
			TargetsPod: true, ConsoleTargetPodUID: pod.UID, Age: 5 * time.Second, CreatedAt: time.Now().Add(-5 * time.Second), AnomalyScore: .95}}}
	pol := model.Policy{Tenant: "voice", Namespace: "voice", PolicyName: "voice-defense", PolicyUID: pod.VoiceAdmissionObservation.PolicyUID, PolicyGeneration: 1,
		Mode: "active", TraceEnabled: true, MaxMovesPerTick: 1, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, Lambda: .4,
		CostCeiling: model.DefaultCostCeiling, MinAvailableReplicas: 1, ProactiveFloor: 15 * time.Minute, ExposurePressureScale: 15 * time.Minute,
		AntiOverRotationWindow: 90 * time.Second, TickInterval: 10 * time.Second, EventAgeHorizon: time.Hour, EventDriven: true, ReactiveOnly: true,
		AssetWeightFromLabels: func(map[string]string) float64 { return .4 },
		EnabledActions:        map[model.Action]bool{model.ActionVoiceSessionAdmissionEnforce: true, model.ActionRotate: true, model.ActionQuarantine: true}}
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
	if !seen[model.ActionVoiceSessionAdmissionEnforce] || !seen[model.ActionRotate] || !seen[model.ActionQuarantine] {
		t.Fatalf("normal policy alternatives absent: candidates=%+v excluded=%+v", set.Candidates, set.Excluded)
	}
	foundCover := false
	for _, c := range set.Candidates {
		if c.Action == model.ActionVoiceSessionAdmissionEnforce && len(c.CoverKeys) > 0 {
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
	if !decisions[0].Selected || decisions[0].Action != model.ActionVoiceSessionAdmissionEnforce {
		t.Fatalf("normal active policy did not select admission boundary: %+v", decisions[0])
	}
	if decisions[0].VoiceAdmissionObservation == nil || decisions[0].VoiceAdmissionObservation.EventUID != pod.VoiceAdmissionObservation.EventUID {
		t.Fatalf("Voice decision lost observed event identity: %+v", decisions[0])
	}
	pol.PolicyUID = "77777777-7777-4777-8777-777777777777"
	wrong, _ := engine.AssembleSet([]*model.WorkloadView{v}, pol)
	for _, c := range wrong.Candidates {
		if c.Action == model.ActionVoiceSessionAdmissionEnforce {
			t.Fatal("wrong selecting policy kept Voice candidate")
		}
	}
}

func boundVoiceAdmissionView() *model.WorkloadView {
	uid := "11111111-1111-4111-8111-111111111111"
	sha := strings.Repeat("a", 64)
	a := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceadmissionpolicy.ScenarioID, CaseID: "unsigned-audio", RunSHA256: sha, SessionID: uid, DeploymentUID: uid, PodUID: uid, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, PolicyCMUID: uid, PolicyResourceVersion: "1", RuleSHA256: sha, SecurityPolicyUID: uid, SecurityPolicyGeneration: 1, ObservedAtUnixMs: 1, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: 1, SentAudioBytes: 1, ReceiptSHA256: sha, ProviderEvidenceSHA256: sha}
	return &model.WorkloadView{Pod: model.Pod{Namespace: "voice", Name: "voice", UID: uid, VoiceAdmissionConfigMap: voiceadmissionpolicy.ConfigMapName, VoiceAdmissionDeploymentUID: uid, VoiceAdmissionSourceSHA256: sha, VoiceAdmissionEventCreator: voiceadmissionpolicy.Creator, VoiceAdmissionObservation: &model.VoiceAdmissionObservation{EventName: "observed", EventUID: uid, CreatorIdentity: voiceadmissionpolicy.Creator, ScenarioID: voiceadmissionpolicy.ScenarioID, EvidenceSource: "TEST_INJECTED", TargetPodUID: uid, DeploymentUID: uid, ConfigMapUID: uid, ConfigMapResourceVersion: "1", SourceSHA256: sha, RuleSHA256: sha, PolicyName: "voice-defense", PolicyUID: uid, PolicyGeneration: 1, SessionID: uid, Assertion: a}}}
}
