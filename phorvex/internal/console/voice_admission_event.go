package console

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	corev1 "k8s.io/api/core/v1"
	"os"
	"time"
)

func (s *Server) createVoiceAdmissionEvent(ctx context.Context, privateDir, caseID, run string, pod corev1.Pod,
	snap voiceAdmissionSnapshot, observed voiceAdmissionReply, when time.Time) (*attackStimulusEvidence, error) {
	if when.IsZero() || time.Since(when) < 0 || time.Since(when) >= 50*time.Second {
		return nil, errors.New("real unsigned provider observation stale")
	}
	if _, landed := voiceAdmissionFirstLoss(observed, snap, string(pod.UID), run); !landed {
		return nil, errors.New("actual unsigned provider and outbound audio observation incomplete")
	}
	id, err := voiceMemoryID()
	if err != nil {
		return nil, err
	}
	name := "voice-admission-" + id
	if observed.Loss == nil {
		return nil, errors.New("immutable unsigned evidence missing")
	}
	v, provider := observed.Loss.Session, observed.Loss.Provider
	assertion := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceAdmissionScenario, CaseID: caseID,
		RunSHA256: voiceMCPStringSHA(run), SessionID: v.SessionID, DeploymentUID: snap.DeploymentUID, PodUID: string(pod.UID),
		AdmissionSourceSHA256: snap.Rule.AdmissionSourceSHA256, LegacyBundleSHA256: snap.Rule.LegacyBundleSHA256, AuthProfileSHA256: snap.Rule.AuthProfileSHA256,
		PolicyCMUID: snap.ConfigMapUID, PolicyResourceVersion: snap.ConfigMapRV, RuleSHA256: snap.RuleSHA256, SelectedRevision: 0,
		SecurityPolicyUID: snap.PolicyUID, SecurityPolicyGeneration: snap.PolicyGeneration, ObservedAtUnixMs: when.UnixMilli(), EvidenceSource: "TEST_INJECTED", Observed: true, Authenticated: false,
		SentAudioFrames: v.SentAudioFrames, SentAudioBytes: v.SentAudioBytes, ReceiptSHA256: voiceMCPSHA(voiceAdmissionCanonical(v)), ProviderEvidenceSHA256: voiceMCPSHA(voiceAdmissionCanonical(provider))}
	if !assertion.Valid() || voiceadmissionpolicy.ValidateEvidence(*observed.Loss, assertion) != nil {
		return nil, errors.New("unsigned real provider observation invalid")
	}
	observation := voiceAdmissionCanonical(assertion)
	object := map[string]any{"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name, "labels": map[string]string{"phorvex.ai/redteam": "true", "phorvex.ai/attack-correlation": id},
			"annotations": map[string]string{model.ConsoleTargetPodUIDAnnotation: string(pod.UID), voiceadmissionpolicy.EventAnnotation: string(observation)}},
		"spec": map[string]any{"description": "TEST_INJECTED after actual unsigned Voice STT/model/TTS and outbound audio",
			"targets": []string{"voice/" + pod.Name}, "rule": map[string]any{"type": voiceadmissionpolicy.EventType, "threatLevel": "critical", "source": "redteam"}, "anomalyScore": "0.95"}}
	manifest, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	if err = voiceMemorySavePrivate(privateDir, "event-intent.json", object); err != nil {
		return nil, errors.New("admission event intent not retained")
	}
	candidate := &attackStimulusEvidence{Kind: "test-injected-after-real-unsigned-voice-provider-use", TargetUID: string(pod.UID),
		EventName: name, EventRule: voiceadmissionpolicy.EventType, Correlation: id, BehavioralExecuted: true,
		Limitation: "bounded unsigned media pipeline access; telephone network and stolen-signature replay were not tested"}
	candidate.createManifest = manifest
	file, err := os.CreateTemp("", "voice-admission-event-*.json")
	if err != nil {
		return candidate, err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(manifest)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return candidate, errors.New("admission event manifest unavailable")
	}
	raw, err := s.cfg.execText(10*time.Second, "kubectl", "create", "-f", file.Name(), "-o", "json")
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		return candidate, errors.New("admission event create ambiguous; exact candidate may exist")
	}
	candidate.createReply = []byte(raw)
	if voiceMemorySavePrivate(privateDir, "event-create-reply.json", json.RawMessage(raw)) != nil {
		return candidate, errors.New("admission create reply not retained")
	}
	var created vllmSecurityEvent
	if json.Unmarshal([]byte(raw), &created) != nil || created.Metadata.Name != name || created.Metadata.Namespace != "" ||
		created.Metadata.UID == "" || created.Metadata.CreationTimestamp == "" ||
		created.Metadata.Annotations["phorvex.ai/creator-identity"] != snap.EventCreator ||
		created.Metadata.Annotations[model.ConsoleTargetPodUIDAnnotation] != string(pod.UID) ||
		created.Metadata.Annotations[voiceadmissionpolicy.EventAnnotation] != string(observation) ||
		len(created.Spec.Targets) != 1 || created.Spec.Targets[0] != "voice/"+pod.Name || created.Spec.Rule.Type != voiceadmissionpolicy.EventType {
		return candidate, errors.New("admission created event admission identity differs")
	}
	candidate.EventUID, candidate.EventCreatedAt, candidate.Observed = created.Metadata.UID, created.Metadata.CreationTimestamp, true
	_ = ctx
	return candidate, nil
}
