package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voicemcppolicy"
)

const voiceMCPHorizon = time.Minute

type voiceMCPPayload struct {
	Version                  int       `json:"version"`
	ScenarioID               string    `json:"scenarioId"`
	RunSHA256                string    `json:"runSHA256"`
	ToolName                 string    `json:"toolName"`
	ObservedDescriptorSHA256 string    `json:"observedDescriptorSHA256"`
	GoodDescriptorSHA256     string    `json:"goodDescriptorSHA256"`
	DeploymentUID            string    `json:"deploymentUID"`
	PodUID                   string    `json:"podUID"`
	SourceSHA256             string    `json:"sourceSHA256"`
	MCPDeploymentUID         string    `json:"mcpDeploymentUID"`
	MCPPodUID                string    `json:"mcpPodUID"`
	MCPServiceUID            string    `json:"mcpServiceUID"`
	MCPConfigMapUID          string    `json:"mcpConfigMapUID"`
	MCPSourceSHA256          string    `json:"mcpSourceSHA256"`
	PolicyName               string    `json:"policyName"`
	PolicyUID                string    `json:"policyUID"`
	PolicyGeneration         int64     `json:"policyGeneration"`
	ObservedAt               time.Time `json:"observedAt"`
	EvidenceSource           string    `json:"evidenceSource"`
	MCPFetchObserved         bool      `json:"mcpFetchObserved"`
	VoiceBehaviorObserved    bool      `json:"voiceBehaviorObserved"`
}

func decodeVoiceMCPPayload(raw string) (voiceMCPPayload, bool) {
	if len(raw) == 0 || len(raw) > 4096 {
		return voiceMCPPayload{}, false
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return voiceMCPPayload{}, false
	}
	allowed := map[string]bool{"version": true, "scenarioId": true, "runSHA256": true, "toolName": true, "observedDescriptorSHA256": true,
		"goodDescriptorSHA256": true, "deploymentUID": true, "podUID": true, "sourceSHA256": true, "mcpDeploymentUID": true,
		"mcpPodUID": true, "mcpServiceUID": true, "mcpConfigMapUID": true, "mcpSourceSHA256": true, "policyName": true,
		"policyUID": true, "policyGeneration": true, "observedAt": true, "evidenceSource": true, "mcpFetchObserved": true, "voiceBehaviorObserved": true}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return voiceMCPPayload{}, false
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return voiceMCPPayload{}, false
		}
		seen[name] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return voiceMCPPayload{}, false
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return voiceMCPPayload{}, false
	}
	if _, err := dec.Token(); err != io.EOF || len(seen) != len(allowed) {
		return voiceMCPPayload{}, false
	}
	var payload voiceMCPPayload
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	if typed.Decode(&payload) != nil {
		return voiceMCPPayload{}, false
	}
	return payload, true
}

func voiceMCPRequiredMode(pod *corev1.Pod, sourceName string) bool {
	if pod == nil || sourceName == "" {
		return false
	}
	var bot *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "bot" {
			bot = &pod.Spec.Containers[i]
		}
	}
	if bot == nil {
		return false
	}
	required := 0
	boundURL := 0
	for _, variable := range bot.Env {
		if variable.Name == "VOICE_MCP_POLICY_REQUIRED" {
			if variable.Value != "true" || variable.ValueFrom != nil {
				return false
			}
			required++
		}
		if variable.Name == "MCP_URL" {
			if variable.Value != voicemcppolicy.InstalledMCPURL || variable.ValueFrom != nil {
				return false
			}
			boundURL++
		}
	}
	if required != 1 || boundURL != 1 {
		return false
	}
	sourceVolume := ""
	policyVolume := ""
	for _, volume := range pod.Spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == sourceName && (volume.ConfigMap.Optional == nil || !*volume.ConfigMap.Optional) {
			sourceVolume = volume.Name
		}
		if volume.ConfigMap != nil && volume.ConfigMap.Name == voicemcppolicy.ConfigMapName && (volume.ConfigMap.Optional == nil || !*volume.ConfigMap.Optional) {
			policyVolume = volume.Name
		}
	}
	if sourceVolume == "" || policyVolume == "" {
		return false
	}
	found := map[string]bool{}
	for _, mount := range bot.VolumeMounts {
		if mount.Name == policyVolume && mount.MountPath == "/etc/phorvex/voice-mcp-tool-policy" && mount.ReadOnly && mount.SubPath == "" {
			found["policy"] = true
		}
		for _, name := range []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"} {
			if mount.Name == sourceVolume && mount.MountPath == "/app/"+name && mount.ReadOnly && mount.SubPath == name {
				found[name] = true
			}
		}
	}
	return len(found) == 5
}

func bindVoiceMCPObservation(ctx context.Context, reader client.Reader, pod *model.Pod, events []model.SecurityEventInfo) {
	pod.VoiceMCPObservation = nil
	if reader == nil || pod.Namespace != voicemcppolicy.Namespace || pod.UID == "" || pod.VoiceMCPConfigMap != voicemcppolicy.ConfigMapName ||
		!voicemcppolicy.ValidSHA(pod.VoiceMCPSourceSHA256) || len(events) == 0 {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload voiceMCPPayload
	for i := range events {
		event := &events[i]
		if event.Trust != TrustTrusted || !event.TargetsPod || event.Type != model.AttackVectorVoiceMCP || event.CreatorIdentity == "" ||
			event.Name == "" || event.UID == "" || event.TimestampMissing || event.Age < 0 || event.Age >= voiceMCPHorizon || event.ConsoleTargetPodUID != pod.UID {
			continue
		}
		parsed, ok := decodeVoiceMCPPayload(event.VoiceMCPRaw)
		if !ok || parsed.Version != 1 || parsed.ScenarioID != "ai2-mcp-tool-poisoning" || !voicemcppolicy.ValidSHA(parsed.RunSHA256) ||
			parsed.ToolName != voicemcppolicy.StoreDirectory || parsed.GoodDescriptorSHA256 != voicemcppolicy.StoreDirectoryGoodSHA256 ||
			!voicemcppolicy.ValidSHA(parsed.ObservedDescriptorSHA256) || parsed.ObservedDescriptorSHA256 == parsed.GoodDescriptorSHA256 ||
			parsed.PodUID != pod.UID || parsed.SourceSHA256 != pod.VoiceMCPSourceSHA256 || !voicemcppolicy.ValidUID(parsed.DeploymentUID) ||
			!voicemcppolicy.ValidUID(parsed.MCPDeploymentUID) || !voicemcppolicy.ValidUID(parsed.MCPPodUID) ||
			!voicemcppolicy.ValidUID(parsed.MCPServiceUID) || !voicemcppolicy.ValidUID(parsed.MCPConfigMapUID) ||
			!voicemcppolicy.ValidSHA(parsed.MCPSourceSHA256) || parsed.PolicyName != "voice-defense" || !voicemcppolicy.ValidUID(parsed.PolicyUID) || parsed.PolicyGeneration <= 0 ||
			parsed.EvidenceSource != "TEST_INJECTED" || !parsed.MCPFetchObserved || !parsed.VoiceBehaviorObserved ||
			parsed.ObservedAt.IsZero() || parsed.ObservedAt.After(event.CreatedAt.Add(time.Second)) ||
			parsed.ObservedAt.After(event.CreatedAt.Add(event.Age)) || event.CreatedAt.Sub(parsed.ObservedAt) > voiceMCPHorizon ||
			event.CreatedAt.Add(event.Age).Sub(parsed.ObservedAt) >= voiceMCPHorizon {
			continue
		}
		if chosen != nil {
			return
		}
		chosen, payload = event, parsed
	}
	if chosen == nil {
		return
	}
	live := &corev1.Pod{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, live) != nil || string(live.UID) != pod.UID ||
		live.DeletionTimestamp != nil || live.Annotations["phorvex.ai/voice-mcp-policy-configmap"] != pod.VoiceMCPConfigMap ||
		live.Annotations["phorvex.ai/voice-mcp-source-sha256"] != pod.VoiceMCPSourceSHA256 ||
		live.Annotations["phorvex.ai/voice-mcp-event-creator"] != chosen.CreatorIdentity {
		return
	}
	dep, ok := voiceRefundDeployment(ctx, reader, live)
	if !ok || dep.DeletionTimestamp != nil || string(dep.UID) != payload.DeploymentUID {
		return
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: payload.PolicyName}, pol) != nil || string(pol.UID) != payload.PolicyUID ||
		pol.Generation != payload.PolicyGeneration || pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(live.Labels)) {
		return
	}
	enabled := false
	for _, action := range pol.Spec.Actions.Enabled {
		enabled = enabled || action == v1alpha1.ActionVoiceMCPToolPin
	}
	if !enabled {
		return
	}
	var sourceName string
	for _, volume := range live.Spec.Volumes {
		if volume.ConfigMap != nil && strings.HasPrefix(volume.ConfigMap.Name, "voice-memory-source-") {
			if sourceName != "" {
				return
			}
			sourceName = volume.ConfigMap.Name
		}
	}
	if !voiceMCPRequiredMode(live, sourceName) || !voiceMCPRequiredMode(&corev1.Pod{Spec: dep.Spec.Template.Spec}, sourceName) ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-policy-configmap"] != voicemcppolicy.ConfigMapName ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-source-configmap"] != sourceName ||
		live.Annotations["phorvex.ai/voice-mcp-source-configmap"] != sourceName ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-source-sha256"] != payload.SourceSHA256 ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-event-creator"] != chosen.CreatorIdentity {
		return
	}
	sourceCM := &corev1.ConfigMap{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: sourceName}, sourceCM) != nil {
		return
	}
	computed, err := voicemcppolicy.RuntimeSourceSHA(sourceCM)
	bundleDigest, bundleErr := voicemcppolicy.BundleSourceSHA(sourceCM)
	if err != nil || bundleErr != nil || computed != payload.SourceSHA256 || sourceName != "voice-memory-source-"+bundleDigest[:12] || sourceCM.UID == "" {
		return
	}
	cm := &corev1.ConfigMap{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.VoiceMCPConfigMap}, cm) != nil || cm.DeletionTimestamp != nil ||
		len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller ||
		cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Name != dep.Name || cm.OwnerReferences[0].Kind != "Deployment" ||
		cm.OwnerReferences[0].APIVersion != "apps/v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.UID == "" || cm.ResourceVersion == "" {
		return
	}
	rule, err := voicemcppolicy.Parse(cm.Data[voicemcppolicy.RuleKey])
	if err != nil || rule.DeploymentUID != payload.DeploymentUID || rule.PolicyUID != payload.PolicyUID || rule.SourceSHA256 != payload.SourceSHA256 {
		return
	}
	for _, entry := range rule.Entries {
		if entry.ToolName == payload.ToolName {
			return
		}
	}
	mcpSource, err := voicemcppolicy.CurrentSourceForObservation(ctx, reader, voicemcppolicy.SourcePins{DeploymentUID: payload.MCPDeploymentUID,
		PodUID: payload.MCPPodUID, ServiceUID: payload.MCPServiceUID, ConfigMapUID: payload.MCPConfigMapUID, SourceSHA256: payload.MCPSourceSHA256})
	if err != nil {
		return
	}
	pod.VoiceMCPDeploymentUID = payload.DeploymentUID
	pod.VoiceMCPObservation = &model.VoiceMCPObservation{EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		ScenarioID: payload.ScenarioID, RunSHA256: payload.RunSHA256, TargetPodUID: pod.UID, DeploymentUID: payload.DeploymentUID,
		ConfigMapUID: string(cm.UID), ConfigMapResourceVersion: cm.ResourceVersion, SourceConfigMapUID: string(sourceCM.UID),
		RuleSHA256: rule.SHA256(), SourceSHA256: payload.SourceSHA256, ToolName: payload.ToolName,
		GoodDescriptorSHA256: payload.GoodDescriptorSHA256, ObservedDescriptorSHA256: payload.ObservedDescriptorSHA256,
		MCPServiceName: voicemcppolicy.MCPServiceName, MCPServiceUID: payload.MCPServiceUID, MCPPodName: mcpSource.PodName,
		MCPPodUID: payload.MCPPodUID, MCPDeploymentUID: payload.MCPDeploymentUID, MCPConfigMapUID: payload.MCPConfigMapUID,
		MCPSourceSHA256: payload.MCPSourceSHA256, PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID,
		PolicyGeneration: payload.PolicyGeneration, SelectedRevision: rule.Revision, ObservedAt: payload.ObservedAt}
}
