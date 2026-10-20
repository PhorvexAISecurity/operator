package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	if p.Namespace == outputpolicy.LiteNamespace {
		bindLiteOutputObservation(ctx, reader, p, events)
		return
	}
	if p.UID == "" || p.OutputPolicyConfigMap == "" || p.OutputPolicyRuleSHA256 == "" || len(events) == 0 || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload sensitiveOutputPayload
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorSensitiveOutput ||
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

func bindLiteOutputObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	if p.UID == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var assertion outputpolicy.LiteObservation
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorSensitiveOutput ||
			e.CreatorIdentity != litellmConsoleCreator || e.Name == "" || e.UID == "" || e.TimestampMissing ||
			e.Age < 0 || e.Age >= sensitiveOutputHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		o, err := outputpolicy.ParseLiteObservation(e.SensitiveOutputV2Raw)
		if err != nil || o.TargetPodUID != p.UID || o.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			e.CreatedAt.Sub(o.ObservedAt) > sensitiveOutputHorizon || e.CreatedAt.Add(e.Age).Sub(o.ObservedAt) >= sensitiveOutputHorizon {
			continue
		}
		if chosen != nil {
			return
		}
		chosen, assertion = e, o
	}
	if chosen == nil {
		return
	}
	live, err := litellmclient.ValidateLive(ctx, reader, assertion.TargetPodUID, assertion.PeerPodUID)
	if err != nil || live.ServiceUID != assertion.ServiceUID || live.SourceSHA256 != assertion.SourceSHA256 || len(live.Pods) != 2 {
		return
	}
	deployment := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: "litellm"}, deployment); err != nil ||
		deployment.DeletionTimestamp != nil || string(deployment.UID) != assertion.DeploymentUID {
		return
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: assertion.PolicyName}, policy); err != nil ||
		string(policy.UID) != assertion.PolicyUID || policy.Generation != assertion.PolicyGeneration {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() {
		return
	}
	currentPod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, currentPod); err != nil ||
		string(currentPod.UID) != p.UID || !selector.Matches(labels.Set(currentPod.Labels)) ||
		!liteOutputPodOwner(ctx, reader, currentPod, assertion.DeploymentUID) {
		return
	}
	if len(live.Pods) != 2 {
		return
	}
	for _, serving := range live.Pods {
		pod := &corev1.Pod{}
		if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: serving.Name}, pod) != nil || string(pod.UID) != serving.UID ||
			!selector.Matches(labels.Set(pod.Labels)) || !liteOutputPodOwner(ctx, reader, pod, assertion.DeploymentUID) ||
			pod.Annotations["phorvex.ai/litellm-output-policy-configmap-uid"] != assertion.PolicyConfigMapUID ||
			pod.Annotations["phorvex.ai/litellm-output-"+map[bool]string{true: "document", false: "prompt"}[assertion.ObjectiveID == outputpolicy.LiteDocumentObjective]+"-secret-uid"] != assertion.ContextSecretUID {
			return
		}
	}
	ruleCM := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: assertion.RuleConfigMapName}, ruleCM); err != nil ||
		!outputpolicy.LiteOwner(ruleCM, assertion.DeploymentUID) || ruleCM.Immutable == nil || !*ruleCM.Immutable ||
		string(ruleCM.UID) != assertion.RuleConfigMapUID || len(ruleCM.Data) != 2 {
		return
	}
	rule, err := outputpolicy.ParseLiteRule(ruleCM.Data[outputpolicy.LiteRuleKey])
	if err != nil || rule.SHA256() != assertion.RuleSHA256 || rule.ObjectiveID != assertion.ObjectiveID || rule.RunNonce != assertion.RunNonce ||
		rule.ProtectedSHA256 != assertion.ProtectedSHA256 || rule.SourceSHA256 != assertion.SourceSHA256 ||
		rule.ServiceUID != assertion.ServiceUID || rule.DeploymentUID != assertion.DeploymentUID ||
		rule.TargetPodUID != assertion.TargetPodUID || rule.PeerPodUID != assertion.PeerPodUID ||
		rule.ContextSecretUID != assertion.ContextSecretUID || rule.ContextSeedSHA256 != assertion.ContextSeedSHA256 {
		return
	}
	if outputpolicy.ValidateLiteAllocation(ruleCM.Data, rule, assertion.OriginalCompletionSHA256, assertion.ObservedAt) != nil {
		return
	}
	shared := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: outputpolicy.LitePolicyConfigMap}, shared); err != nil ||
		!outputpolicy.LiteOwner(shared, assertion.DeploymentUID) || string(shared.UID) != assertion.PolicyConfigMapUID || len(shared.Data) != 1 {
		return
	}
	state, err := outputpolicy.ParseLiteState(shared.Data[outputpolicy.LitePolicyKey])
	if err != nil || len(state.Entries) >= outputpolicy.LiteMaxEntries {
		return
	}
	for _, entry := range state.Entries {
		if entry.Key() == assertion.ObjectiveID+"/"+assertion.RunNonce {
			return
		}
	}
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: outputpolicy.LiteObjectiveSecret(assertion.ObjectiveID)}, secret); err != nil ||
		secret.Immutable == nil || !*secret.Immutable || string(secret.UID) != assertion.ContextSecretUID || len(secret.Data) != 1 || len(secret.Data["seed"]) < 32 || len(secret.Data["seed"]) > 64 ||
		outputpolicy.LiteSHA(secret.Data["seed"]) != assertion.ContextSeedSHA256 {
		return
	}
	owner := metav1.GetControllerOf(secret)
	if owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" || owner.Name != "litellm" || string(owner.UID) != assertion.DeploymentUID {
		return
	}
	p.OutputPolicyObservation = &model.SensitiveOutputObservation{
		Version: 2, EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		TargetPodUID: p.UID, ConfigMapUID: assertion.PolicyConfigMapUID, SelectedRevision: state.Revision,
		SelectedConfigMapResourceVersion: shared.ResourceVersion, PolicyName: assertion.PolicyName,
		PolicyUID: assertion.PolicyUID, PolicyGeneration: assertion.PolicyGeneration,
		RuleSHA256: assertion.RuleSHA256, ObservedAt: assertion.ObservedAt,
		LiteLLM: &model.LiteOutputObservation{ObjectiveID: assertion.ObjectiveID, RunNonce: assertion.RunNonce,
			PeerPodUID: assertion.PeerPodUID, RuleConfigMapName: assertion.RuleConfigMapName, RuleConfigMapUID: assertion.RuleConfigMapUID,
			RuleSHA256: assertion.RuleSHA256, ProtectedSHA256: assertion.ProtectedSHA256, SourceSHA256: assertion.SourceSHA256,
			ServiceUID: assertion.ServiceUID, DeploymentUID: assertion.DeploymentUID,
			ContextSecretUID: assertion.ContextSecretUID, ContextSeedSHA256: assertion.ContextSeedSHA256,
			RequestSHA256: assertion.RequestSHA256, OriginalCompletionSHA256: assertion.OriginalCompletionSHA256},
	}
}

func liteOutputPodOwner(ctx context.Context, reader client.Reader, pod *corev1.Pod, deploymentUID string) bool {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" || owner.UID == "" {
		return false
	}
	rs := &appsv1.ReplicaSet{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs) != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return false
	}
	parent := metav1.GetControllerOf(rs)
	return parent != nil && parent.APIVersion == "apps/v1" && parent.Kind == "Deployment" && parent.Name == "litellm" && string(parent.UID) == deploymentUID
}
