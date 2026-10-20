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

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
)

const voiceRefundHorizon = 60 * time.Second

type voiceRefundPayload struct {
	Version               int       `json:"version"`
	ScenarioID            string    `json:"scenarioId"`
	CaseID                string    `json:"caseId"`
	AssertedCallerSHA256  string    `json:"assertedCallerSHA256"`
	OrderSHA256           string    `json:"orderSHA256"`
	DeploymentUID         string    `json:"deploymentUID"`
	PodUID                string    `json:"podUID"`
	SourceSHA256          string    `json:"sourceSHA256"`
	PolicyName            string    `json:"policyName"`
	PolicyUID             string    `json:"policyUID"`
	PolicyGeneration      int64     `json:"policyGeneration"`
	ObservedAt            time.Time `json:"observedAt"`
	EvidenceSource        string    `json:"evidenceSource"`
	ModelCallbackObserved bool      `json:"modelCallbackObserved"`
	CRMSideEffectObserved bool      `json:"crmSideEffectObserved"`
}

func decodeVoiceRefundPayload(raw string) (voiceRefundPayload, bool) {
	if len(raw) == 0 || len(raw) > 2048 {
		return voiceRefundPayload{}, false
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return voiceRefundPayload{}, false
	}
	allowed := map[string]bool{"version": true, "scenarioId": true, "caseId": true, "assertedCallerSHA256": true, "orderSHA256": true, "deploymentUID": true, "podUID": true, "sourceSHA256": true, "policyName": true, "policyUID": true, "policyGeneration": true, "observedAt": true, "evidenceSource": true, "modelCallbackObserved": true, "crmSideEffectObserved": true}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return voiceRefundPayload{}, false
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return voiceRefundPayload{}, false
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return voiceRefundPayload{}, false
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return voiceRefundPayload{}, false
	}
	if _, err := dec.Token(); err != io.EOF || len(seen) != len(allowed) {
		return voiceRefundPayload{}, false
	}
	var payload voiceRefundPayload
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	if typed.Decode(&payload) != nil {
		return voiceRefundPayload{}, false
	}
	return payload, true
}

func voiceRefundDeployment(ctx context.Context, reader client.Reader, pod *corev1.Pod) (*appsv1.Deployment, bool) {
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

func bindVoiceRefundObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.VoiceRefundObservation = nil
	if reader == nil || p.Namespace != voicerefundpolicy.Namespace || p.UID == "" || p.VoiceRefundConfigMap != voicerefundpolicy.ConfigMapName ||
		!voicerefundpolicy.ValidSHA(p.VoiceRefundSourceSHA256) || len(events) == 0 {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload voiceRefundPayload
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorVoiceRefund ||
			e.CreatorIdentity == "" || e.Name == "" || e.UID == "" || e.TimestampMissing ||
			e.Age < 0 || e.Age >= voiceRefundHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		parsed, ok := decodeVoiceRefundPayload(e.VoiceRefundRaw)
		if !ok || parsed.Version != 1 || parsed.EvidenceSource != "TEST_INJECTED" || !parsed.ModelCallbackObserved || !parsed.CRMSideEffectObserved ||
			parsed.ScenarioID == "" || parsed.CaseID == "" || !voicerefundpolicy.ValidSHA(parsed.AssertedCallerSHA256) ||
			!voicerefundpolicy.ValidSHA(parsed.OrderSHA256) || parsed.PodUID != p.UID ||
			parsed.SourceSHA256 != p.VoiceRefundSourceSHA256 || !voicerefundpolicy.ValidUID(parsed.DeploymentUID) ||
			parsed.PolicyName == "" || !voicerefundpolicy.ValidUID(parsed.PolicyUID) || parsed.PolicyGeneration <= 0 ||
			parsed.ObservedAt.IsZero() || parsed.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			parsed.ObservedAt.After(e.CreatedAt.Add(e.Age)) || e.CreatedAt.Sub(parsed.ObservedAt) > voiceRefundHorizon ||
			e.CreatedAt.Add(e.Age).Sub(parsed.ObservedAt) >= voiceRefundHorizon {
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
		live.Annotations["phorvex.ai/voice-refund-policy-configmap"] != p.VoiceRefundConfigMap ||
		live.Annotations["phorvex.ai/voice-refund-source-sha256"] != p.VoiceRefundSourceSHA256 ||
		live.Annotations["phorvex.ai/voice-refund-event-creator"] != chosen.CreatorIdentity ||
		!voiceRefundRequiredPolicyMode(live) {
		return
	}
	dep, ok := voiceRefundDeployment(ctx, reader, live)
	if !ok || string(dep.UID) != payload.DeploymentUID {
		return
	}
	if voiceadmissionpolicy.HasWrapperAuthority(live) {
		if _, err := voiceadmissionpolicy.VerifySource(ctx, reader, live, dep); err != nil {
			return
		}
	}
	cm := &corev1.ConfigMap{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.VoiceRefundConfigMap}, cm) != nil || cm.DeletionTimestamp != nil ||
		len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller ||
		cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Name != dep.Name ||
		cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].APIVersion != "apps/v1" ||
		len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return
	}
	rule, err := voicerefundpolicy.Parse(cm.Data[voicerefundpolicy.RuleKey])
	if err != nil || rule.DeploymentUID != payload.DeploymentUID || rule.PolicyUID != payload.PolicyUID || rule.SourceSHA256 != payload.SourceSHA256 {
		return
	}
	for _, entry := range rule.Entries {
		if entry.AssertedCallerSHA256 == payload.AssertedCallerSHA256 && entry.OrderSHA256 == payload.OrderSHA256 {
			return
		}
	}
	p.VoiceRefundDeploymentUID = payload.DeploymentUID
	p.VoiceRefundObservation = &model.VoiceRefundObservation{EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity, ScenarioID: payload.ScenarioID, CaseID: payload.CaseID,
		TargetPodUID: p.UID, DeploymentUID: payload.DeploymentUID, ConfigMapUID: string(cm.UID), ConfigMapResourceVersion: cm.ResourceVersion,
		RuleSHA256: rule.SHA256(), SourceSHA256: payload.SourceSHA256, AssertedCallerSHA256: payload.AssertedCallerSHA256, OrderSHA256: payload.OrderSHA256,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		SelectedRevision: rule.Revision, ObservedAt: payload.ObservedAt}
}

func voiceRefundRequiredPolicyMode(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name != "bot" {
			continue
		}
		count := 0
		for _, variable := range container.Env {
			if variable.Name != "VOICE_REFUND_POLICY_REQUIRED" {
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
