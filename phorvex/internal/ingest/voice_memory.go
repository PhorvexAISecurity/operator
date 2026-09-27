package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voicememorypolicy"
)

const voiceMemoryHorizon = 60 * time.Second

type voiceMemoryPayload struct {
	Version          int       `json:"version"`
	ScenarioID       string    `json:"scenarioId"`
	CaseID           string    `json:"caseId"`
	CallerID         string    `json:"callerId"`
	NoteSHA256       string    `json:"noteSHA256"`
	DeploymentUID    string    `json:"deploymentUID"`
	PodUID           string    `json:"podUID"`
	SourceSHA256     string    `json:"sourceSHA256"`
	PolicyName       string    `json:"policyName"`
	PolicyUID        string    `json:"policyUID"`
	PolicyGeneration int64     `json:"policyGeneration"`
	ObservedAt       time.Time `json:"observedAt"`
	EvidenceSource   string    `json:"evidenceSource"`
	Observed         bool      `json:"observed"`
}

func decodeVoiceMemoryPayload(raw string) (voiceMemoryPayload, bool) {
	if len(raw) == 0 || len(raw) > 2048 {
		return voiceMemoryPayload{}, false
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return voiceMemoryPayload{}, false
	}
	allowed := map[string]bool{"version": true, "scenarioId": true, "caseId": true, "callerId": true, "noteSHA256": true, "deploymentUID": true, "podUID": true, "sourceSHA256": true, "policyName": true, "policyUID": true, "policyGeneration": true, "observedAt": true, "evidenceSource": true, "observed": true}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return voiceMemoryPayload{}, false
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return voiceMemoryPayload{}, false
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return voiceMemoryPayload{}, false
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return voiceMemoryPayload{}, false
	}
	if _, err := dec.Token(); err != io.EOF || len(seen) != len(allowed) {
		return voiceMemoryPayload{}, false
	}
	var payload voiceMemoryPayload
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	if typed.Decode(&payload) != nil {
		return voiceMemoryPayload{}, false
	}
	return payload, true
}

func voiceMemoryDeployment(ctx context.Context, reader client.Reader, pod *corev1.Pod) (*appsv1.Deployment, bool) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" || len(pod.OwnerReferences) != 1 {
		return nil, false
	}
	rs := &appsv1.ReplicaSet{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs) != nil || rs.UID != owner.UID {
		return nil, false
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || len(rs.OwnerReferences) != 1 {
		return nil, false
	}
	dep := &appsv1.Deployment{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: parent.Name}, dep) != nil || dep.UID != parent.UID {
		return nil, false
	}
	return dep, true
}

func bindVoiceMemoryObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.VoiceMemoryObservation = nil
	if reader == nil || p.Namespace != voicememorypolicy.Namespace || p.UID == "" || p.VoiceMemoryConfigMap != voicememorypolicy.ConfigMapName ||
		!voicememorypolicy.ValidSHA(p.VoiceMemorySourceSHA256) || len(events) == 0 {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload voiceMemoryPayload
	for i := range events {
		e := &events[i]
		if e.Trust != TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorVoiceMemory ||
			e.CreatorIdentity == "" || e.Name == "" || e.UID == "" || e.TimestampMissing ||
			e.Age < 0 || e.Age >= voiceMemoryHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		parsed, ok := decodeVoiceMemoryPayload(e.VoiceMemoryRaw)
		if !ok || parsed.Version != 1 || parsed.EvidenceSource != "TEST_INJECTED" || !parsed.Observed ||
			parsed.ScenarioID == "" || parsed.CaseID == "" || !voicememorypolicy.ValidCaller(parsed.CallerID) ||
			!voicememorypolicy.ValidSHA(parsed.NoteSHA256) || parsed.PodUID != p.UID ||
			parsed.SourceSHA256 != p.VoiceMemorySourceSHA256 || !voicememorypolicy.ValidUID(parsed.DeploymentUID) ||
			parsed.PolicyName == "" || !voicememorypolicy.ValidUID(parsed.PolicyUID) || parsed.PolicyGeneration <= 0 ||
			parsed.ObservedAt.IsZero() || parsed.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			parsed.ObservedAt.After(e.CreatedAt.Add(e.Age)) || e.CreatedAt.Sub(parsed.ObservedAt) > voiceMemoryHorizon ||
			e.CreatedAt.Add(e.Age).Sub(parsed.ObservedAt) >= voiceMemoryHorizon {
			continue
		}
		if chosen != nil {
			return
		}
		chosen, payload = e, parsed
	}
	if chosen == nil {
		return
	}
	live := &corev1.Pod{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, live) != nil || string(live.UID) != p.UID ||
		live.Annotations["phorvex.ai/voice-memory-policy-configmap"] != p.VoiceMemoryConfigMap ||
		live.Annotations["phorvex.ai/voice-memory-source-sha256"] != p.VoiceMemorySourceSHA256 ||
		live.Annotations["phorvex.ai/voice-memory-event-creator"] != chosen.CreatorIdentity ||
		!voiceMemoryRequiredPolicyMode(live) {
		return
	}
	dep, ok := voiceMemoryDeployment(ctx, reader, live)
	if !ok || string(dep.UID) != payload.DeploymentUID {
		return
	}
	cm := &corev1.ConfigMap{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.VoiceMemoryConfigMap}, cm) != nil || len(cm.OwnerReferences) != 1 ||
		cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].APIVersion != "apps/v1" {
		return
	}
	rule, err := voicememorypolicy.Parse(cm.Data[voicememorypolicy.RuleKey])
	if err != nil || rule.DeploymentUID != payload.DeploymentUID || rule.PolicyUID != payload.PolicyUID || rule.SourceSHA256 != payload.SourceSHA256 {
		return
	}
	for _, entry := range rule.Entries {
		if entry.CallerID == payload.CallerID && entry.NoteSHA256 == payload.NoteSHA256 {
			return
		}
	}
	p.VoiceMemoryDeploymentUID = payload.DeploymentUID
	p.VoiceMemoryObservation = &model.VoiceMemoryObservation{EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity, ScenarioID: payload.ScenarioID, CaseID: payload.CaseID,
		TargetPodUID: p.UID, DeploymentUID: payload.DeploymentUID, ConfigMapUID: string(cm.UID), ConfigMapResourceVersion: cm.ResourceVersion,
		RuleSHA256: rule.SHA256(), SourceSHA256: payload.SourceSHA256, CallerID: payload.CallerID, NoteSHA256: payload.NoteSHA256,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		SelectedRevision: rule.Revision, ObservedAt: payload.ObservedAt}
}

func voiceMemoryRequiredPolicyMode(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name != "bot" {
			continue
		}
		count := 0
		for _, variable := range container.Env {
			if variable.Name != "VOICE_MEMORY_POLICY_REQUIRED" {
				continue
			}
			if variable.Value != "true" || variable.ValueFrom != nil {
				return false
			}
			count++
		}
		return count == 1
	}
	return false
}
