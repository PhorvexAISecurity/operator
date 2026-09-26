package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
)

const sensitiveOutputHorizon = 60 * time.Second

type sensitiveOutputPayload struct {
	Version          int       `json:"version"`
	RuleID           string    `json:"ruleId"`
	RuleSHA256       string    `json:"ruleSHA256"`
	ConfigMapUID     string    `json:"configMapUID"`
	PodUID           string    `json:"podUID"`
	PolicyName       string    `json:"policyName"`
	PolicyUID        string    `json:"policyUID"`
	PolicyGeneration int64     `json:"policyGeneration"`
	RequestPath      string    `json:"requestPath"`
	ObservedAt       time.Time `json:"observedAt"`
}

// A flat, small exact object is sufficient here; token scanning rejects
// duplicate names before the typed decoder rejects unknown names and tails.
func decodeSensitiveOutputPayload(raw string) (sensitiveOutputPayload, bool) {
	if len(raw) == 0 || len(raw) > 2048 {
		return sensitiveOutputPayload{}, false
	}
	tokens := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, err := tokens.Token()
	if err != nil || start != json.Delim('{') {
		return sensitiveOutputPayload{}, false
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"version": true, "ruleId": true, "ruleSHA256": true, "configMapUID": true, "podUID": true, "policyName": true, "policyUID": true, "policyGeneration": true, "requestPath": true, "observedAt": true}
	for tokens.More() {
		key, err := tokens.Token()
		if err != nil {
			return sensitiveOutputPayload{}, false
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return sensitiveOutputPayload{}, false
		}
		seen[name] = true
		var value json.RawMessage
		if err := tokens.Decode(&value); err != nil {
			return sensitiveOutputPayload{}, false
		}
	}
	end, err := tokens.Token()
	if err != nil || end != json.Delim('}') {
		return sensitiveOutputPayload{}, false
	}
	if _, err := tokens.Token(); err != io.EOF || len(seen) != 10 {
		return sensitiveOutputPayload{}, false
	}
	var payload sensitiveOutputPayload
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return sensitiveOutputPayload{}, false
	}
	return payload, true
}

// bindSensitiveOutputObservation admits exactly one recent, trusted event
// against a fresh live ConfigMap and the same Pod UID/source pins as the
// snapshot. If the source changes during collection, the fact is absent.
func bindSensitiveOutputObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.OutputPolicyObservation = nil
	if p.UID == "" || p.OutputPolicyConfigMap == "" || p.OutputPolicyRuleSHA256 == "" || len(events) == 0 || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload sensitiveOutputPayload
	for i := range events {
		e := &events[i]
		if e.Trust != TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorSensitiveOutput ||
			e.CreatorIdentity == "" || e.CreatorIdentity != p.OutputEventCreator || e.Name == "" || e.UID == "" || e.TimestampMissing ||
			e.Age < 0 || e.Age >= sensitiveOutputHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		parsed, ok := decodeSensitiveOutputPayload(e.SensitiveOutputRaw)
		if !ok || parsed.Version != 1 || parsed.RuleID != outputpolicy.RuleID ||
			parsed.PolicyName != "guardrail-output-fixture" || parsed.PolicyUID == "" || parsed.PolicyGeneration <= 0 ||
			parsed.RequestPath != outputpolicy.Route || parsed.PodUID != p.UID ||
			parsed.RuleSHA256 != p.OutputPolicyRuleSHA256 || parsed.ConfigMapUID == "" ||
			parsed.ObservedAt.IsZero() || !parsed.ObservedAt.Before(e.CreatedAt.Add(time.Second)) ||
			parsed.ObservedAt.After(e.CreatedAt.Add(e.Age)) ||
			e.CreatedAt.Sub(parsed.ObservedAt) > sensitiveOutputHorizon ||
			e.CreatedAt.Add(e.Age).Sub(parsed.ObservedAt) >= sensitiveOutputHorizon {
			continue
		}
		if chosen != nil { // conflicting/duplicate assertions are not a singleton authority
			return
		}
		chosen, payload = e, parsed
	}
	if chosen == nil {
		return
	}
	livePod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, livePod); err != nil || string(livePod.UID) != p.UID ||
		livePod.Annotations[outputpolicy.PodConfigMapAnnotation] != p.OutputPolicyConfigMap ||
		livePod.Annotations[outputpolicy.PodRuleSHAAnnotation] != p.OutputPolicyRuleSHA256 ||
		livePod.Annotations[outputpolicy.PodProxySHAAnnotation] != p.OutputProxySourceSHA256 ||
		livePod.Annotations[outputpolicy.PodSupportSHAAnnotation] != p.OutputSupportSourceSHA256 {
		return
	}
	if livePod.Annotations["phorvex.ai/output-event-creator"] != p.OutputEventCreator {
		return
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.OutputPolicyConfigMap}, cm); err != nil {
		return
	}
	activation, err := outputpolicy.ValidateConfigMap(cm, livePod)
	if err != nil || activation.Active || string(cm.UID) != payload.ConfigMapUID {
		return
	}
	proxyImage, supportImage := "", ""
	for _, status := range livePod.Status.ContainerStatuses {
		switch status.Name {
		case "guardrail-proxy":
			proxyImage = status.ImageID
		case "support-app":
			supportImage = status.ImageID
		}
	}
	if proxyImage == "" || supportImage == "" {
		return
	}
	p.OutputPolicyObservation = &model.SensitiveOutputObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		TargetPodUID: p.UID, ConfigMapUID: payload.ConfigMapUID,
		SelectedRevision: activation.Revision, SelectedConfigMapResourceVersion: cm.ResourceVersion,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		RuleSHA256: payload.RuleSHA256, ProxySourceSHA256: p.OutputProxySourceSHA256,
		SupportSourceSHA256: p.OutputSupportSourceSHA256, ObservedAt: payload.ObservedAt,
		ProxyImageID: proxyImage, SupportImageID: supportImage,
	}
}
