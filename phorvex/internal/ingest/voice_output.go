package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
)

const voiceOutputHorizon = 60 * time.Second

type voiceOutputPayload struct {
	Version                       int       `json:"version"`
	ScenarioID                    string    `json:"scenarioId"`
	EvidenceSource                string    `json:"evidenceSource"`
	RawModelMarkerObserved        bool      `json:"rawModelMarkerObserved"`
	AssistantOutputMarkerObserved bool      `json:"assistantOutputMarkerObserved"`
	MarkerSHA256                  string    `json:"markerSHA256"`
	ConfigMapUID                  string    `json:"configMapUID"`
	DeploymentUID                 string    `json:"deploymentUID"`
	SourceSHA256                  string    `json:"sourceSHA256"`
	PolicyName                    string    `json:"policyName"`
	PolicyUID                     string    `json:"policyUID"`
	PolicyGeneration              int64     `json:"policyGeneration"`
	PodUID                        string    `json:"podUID"`
	ObservedAt                    time.Time `json:"observedAt"`
	RequestPath                   string    `json:"requestPath"`
}

func decodeVoiceOutputPayload(raw string) (voiceOutputPayload, bool) {
	if len(raw) == 0 || len(raw) > 2048 {
		return voiceOutputPayload{}, false
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return voiceOutputPayload{}, false
	}
	allowed := map[string]bool{"version": true, "scenarioId": true, "evidenceSource": true, "rawModelMarkerObserved": true, "assistantOutputMarkerObserved": true, "markerSHA256": true, "configMapUID": true, "deploymentUID": true, "sourceSHA256": true, "policyName": true, "policyUID": true, "policyGeneration": true, "podUID": true, "observedAt": true, "requestPath": true}
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return voiceOutputPayload{}, false
		}
		name, ok := k.(string)
		if !ok || !allowed[name] || seen[name] {
			return voiceOutputPayload{}, false
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return voiceOutputPayload{}, false
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return voiceOutputPayload{}, false
	}
	if _, err = dec.Token(); err != io.EOF {
		return voiceOutputPayload{}, false
	}
	var p voiceOutputPayload
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	if typed.Decode(&p) != nil {
		return voiceOutputPayload{}, false
	}
	return p, true
}

func voiceOutputRequiredMode(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name != "bot" {
			continue
		}
		count := 0
		for _, v := range c.Env {
			if v.Name == "VOICE_OUTPUT_POLICY_REQUIRED" {
				if v.Value != "true" || v.ValueFrom != nil {
					return false
				}
				count++
			}
		}
		if count != 1 {
			return false
		}
		paths := map[string]string{}
		for _, m := range c.VolumeMounts {
			if m.ReadOnly && m.SubPath == "" {
				paths[m.MountPath] = m.Name
			}
		}
		policyVol, tokenVol := paths["/etc/phorvex/voice-output-policy"], paths["/etc/phorvex/voice-memory-state-token"]
		testTokenVol := paths["/etc/phorvex/voice-output-test-token"]
		if policyVol == "" || tokenVol == "" || testTokenVol == "" {
			return false
		}
		watermark := ""
		for _, m := range c.VolumeMounts {
			if m.MountPath == "/var/lib/phorvex-voice-memory" && m.SubPath == "" {
				watermark = m.Name
			}
		}
		if watermark == "" {
			return false
		}
		valid := 0
		for _, v := range pod.Spec.Volumes {
			if v.Name == policyVol && v.ConfigMap != nil && v.ConfigMap.Name == voiceoutputpolicy.ConfigMapName && (v.ConfigMap.Optional == nil || !*v.ConfigMap.Optional) {
				valid++
			}
			if v.Name == tokenVol && v.Secret != nil && v.Secret.SecretName == "voice-memory-state-token" {
				valid++
			}
			if v.Name == testTokenVol && v.Secret != nil && v.Secret.SecretName == "voice-output-test-token" {
				valid++
			}
			if v.Name == watermark && v.EmptyDir != nil {
				valid++
			}
		}
		return valid == 4
	}
	return false
}

func bindVoiceOutputObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.VoiceOutputObservation = nil
	if reader == nil || p.Namespace != voiceoutputpolicy.Namespace || p.UID == "" || p.VoiceOutputConfigMap != voiceoutputpolicy.ConfigMapName || !voiceoutputpolicy.ValidSHA(p.VoiceOutputSourceSHA256) {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload voiceOutputPayload
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorVoiceOutput || e.CreatorIdentity != "system:serviceaccount:phorvex-system:phorvex-phorvex-console" || e.Name == "" || e.UID == "" || e.TimestampMissing || e.Age < 0 || e.Age >= voiceOutputHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		a, ok := decodeVoiceOutputPayload(e.VoiceOutputRaw)
		if !ok || a.Version != 1 || a.ScenarioID != "ai2-system-prompt-leakage" || a.EvidenceSource != "TEST_INJECTED" || !a.RawModelMarkerObserved || !a.AssistantOutputMarkerObserved || a.RequestPath != "/ws" || !voiceoutputpolicy.ValidSHA(a.MarkerSHA256) || !voiceoutputpolicy.ValidUID(a.ConfigMapUID) || !voiceoutputpolicy.ValidUID(a.DeploymentUID) || !voiceoutputpolicy.ValidUID(a.PolicyUID) || a.PolicyName == "" || a.PolicyGeneration <= 0 || a.PodUID != p.UID || a.SourceSHA256 != p.VoiceOutputSourceSHA256 || a.ObservedAt.IsZero() || a.ObservedAt.After(e.CreatedAt.Add(time.Second)) || a.ObservedAt.After(e.CreatedAt.Add(e.Age)) || e.CreatedAt.Sub(a.ObservedAt) > voiceOutputHorizon || e.CreatedAt.Add(e.Age).Sub(a.ObservedAt) >= voiceOutputHorizon {
			continue
		}
		if chosen != nil {
			return
		}
		chosen, payload = e, a
	}
	if chosen == nil {
		return
	}
	live := &corev1.Pod{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, live) != nil || string(live.UID) != p.UID || live.Annotations["phorvex.ai/voice-output-policy-configmap"] != p.VoiceOutputConfigMap || live.Annotations["phorvex.ai/voice-output-source-sha256"] != p.VoiceOutputSourceSHA256 || live.Annotations["phorvex.ai/voice-output-event-creator"] != chosen.CreatorIdentity || !voiceOutputRequiredMode(live) {
		return
	}
	dep, ok := voiceRefundDeployment(ctx, reader, live)
	if !ok || string(dep.UID) != payload.DeploymentUID {
		return
	}
	source, err := voiceoutputpolicy.VerifySource(ctx, reader, live, dep)
	if err != nil || source.SourceSHA256 != payload.SourceSHA256 {
		return
	}
	cm := &corev1.ConfigMap{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.VoiceOutputConfigMap}, cm) != nil || cm.DeletionTimestamp != nil || string(cm.UID) != payload.ConfigMapUID || len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller || cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Name != dep.Name || cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].APIVersion != "apps/v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return
	}
	rule, err := voiceoutputpolicy.Parse(cm.Data[voiceoutputpolicy.RuleKey])
	if err != nil || rule.ConfigMapUID != payload.ConfigMapUID || rule.DeploymentUID != payload.DeploymentUID || rule.PolicyUID != payload.PolicyUID || rule.SourceSHA256 != payload.SourceSHA256 {
		return
	}
	for _, entry := range rule.Entries {
		if entry.MarkerSHA256 == payload.MarkerSHA256 {
			return
		}
	}
	p.VoiceOutputDeploymentUID = payload.DeploymentUID
	p.VoiceOutputObservation = &model.VoiceOutputObservation{EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity, ScenarioID: payload.ScenarioID, EvidenceSource: payload.EvidenceSource, TargetPodUID: p.UID, DeploymentUID: payload.DeploymentUID, ConfigMapUID: payload.ConfigMapUID, ConfigMapResourceVersion: cm.ResourceVersion, RuleSHA256: rule.SHA256(), SourceSHA256: payload.SourceSHA256, MarkerSHA256: payload.MarkerSHA256, PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration, SelectedRevision: rule.Revision, RawModelMarkerObserved: true, AssistantOutputMarkerObserved: true, ObservedAt: payload.ObservedAt}
}
