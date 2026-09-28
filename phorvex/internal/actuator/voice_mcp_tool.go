package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	"github.com/phorvex/phorvex/internal/voicemcppolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	voiceMCPSecretName      = "voice-memory-state-token"
	voiceMCPJournalLabel    = "phorvex.ai/voice-mcp-journal"
	voiceMCPEventAnnotation = "phorvex.ai/voice-mcp-observation-v1"
	voiceMCPInstalledURL    = voicemcppolicy.InstalledMCPURL
)

type voiceMCPScope struct {
	pod        *corev1.Pod
	deployment *appsv1.Deployment
	policy     *v1alpha1.PhorvexPolicy
	cm         *corev1.ConfigMap
	rule       voicemcppolicy.Rule
	secret     []byte
	pods       []corev1.Pod
	sourceName string
	sourceUID  string
}

func voiceMCPOwner(ctx context.Context, reader client.Reader, pod *corev1.Pod) (*appsv1.Deployment, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || len(pod.OwnerReferences) != 1 || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" {
		return nil, fmt.Errorf("voice MCP Pod owner invalid")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs); err != nil {
		return nil, err
	}
	if rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
		return nil, fmt.Errorf("voice MCP ReplicaSet identity changed")
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" {
		return nil, fmt.Errorf("voice MCP Deployment owner absent")
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: parent.Name}, dep); err != nil {
		return nil, err
	}
	if dep.UID != parent.UID || dep.DeletionTimestamp != nil {
		return nil, fmt.Errorf("voice MCP Deployment identity changed")
	}
	return dep, nil
}

func voiceMCPMounts(pod *corev1.Pod) (string, bool) {
	var bot *corev1.Container
	botCount := 0
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "bot" {
			bot = &pod.Spec.Containers[i]
			botCount++
		}
	}
	if bot == nil || botCount != 1 || (!voiceadmissionpolicy.LegacyCommand(*bot) && !voiceadmissionpolicy.WrapperCommand(*bot)) || bot.Image == "" {
		return "", false
	}
	required := 0
	boundURL := 0
	testEnabled := 0
	serverSource := 0
	for _, variable := range bot.Env {
		if variable.Name == "VOICE_MCP_POLICY_REQUIRED" {
			if variable.Value != "true" || variable.ValueFrom != nil {
				return "", false
			}
			required++
		}
		if variable.Name == "MCP_URL" {
			if variable.Value != voiceMCPInstalledURL || variable.ValueFrom != nil {
				return "", false
			}
			boundURL++
		}
		if variable.Name == "VOICE_MCP_TEST_ENABLED" {
			if variable.Value != "true" || variable.ValueFrom != nil {
				return "", false
			}
			testEnabled++
		}
		if variable.Name == "VOICE_MCP_SERVER_SOURCE_SHA256" {
			if variable.Value != voicemcppolicy.ReviewedMCPSourceSHA256 || variable.ValueFrom != nil {
				return "", false
			}
			serverSource++
		}
	}
	if required != 1 || boundURL != 1 || testEnabled != 1 || serverSource != 1 {
		return "", false
	}
	var policyVolume, secretVolume, sourceVolume, ledgerVolume, testTokenVolume string
	sourceFiles := map[string]string{"/app/bot.py": "bot.py", "/app/voice_memory_policy.py": "voice_memory_policy.py", "/app/voice_output_policy.py": "voice_output_policy.py", "/app/voice_mcp_policy.py": "voice_mcp_policy.py"}
	seen := map[string]bool{}
	for _, mount := range bot.VolumeMounts {
		switch mount.MountPath {
		case "/etc/phorvex/voice-mcp-tool-policy":
			if !mount.ReadOnly || mount.SubPath != "" {
				return "", false
			}
			policyVolume = mount.Name
		case "/etc/phorvex/voice-memory-state-token":
			if !mount.ReadOnly || mount.SubPath != "" {
				return "", false
			}
			secretVolume = mount.Name
		case "/var/lib/phorvex-voice-memory":
			if mount.SubPath != "" {
				return "", false
			}
			ledgerVolume = mount.Name
		case "/etc/phorvex/voice-mcp-test-token":
			if !mount.ReadOnly || mount.SubPath != "" {
				return "", false
			}
			testTokenVolume = mount.Name
		default:
			if file, ok := sourceFiles[mount.MountPath]; ok {
				if !mount.ReadOnly || mount.SubPath != file || sourceVolume != "" && sourceVolume != mount.Name || seen[file] {
					return "", false
				}
				sourceVolume = mount.Name
				seen[file] = true
			}
		}
	}
	if policyVolume == "" || secretVolume == "" || sourceVolume == "" || ledgerVolume == "" || testTokenVolume == "" || len(seen) != len(sourceFiles) {
		return "", false
	}
	var sourceName string
	valid := 0
	for _, volume := range pod.Spec.Volumes {
		switch volume.Name {
		case policyVolume:
			if volume.ConfigMap == nil || volume.ConfigMap.Name != voicemcppolicy.ConfigMapName || volume.ConfigMap.Optional != nil && *volume.ConfigMap.Optional {
				return "", false
			}
			valid++
		case secretVolume:
			if volume.Secret == nil || volume.Secret.SecretName != voiceMCPSecretName {
				return "", false
			}
			valid++
		case sourceVolume:
			if volume.ConfigMap == nil || !strings.HasPrefix(volume.ConfigMap.Name, "voice-memory-source-") || volume.ConfigMap.Optional != nil && *volume.ConfigMap.Optional {
				return "", false
			}
			sourceName = volume.ConfigMap.Name
			valid++
		case ledgerVolume:
			if volume.EmptyDir == nil {
				return "", false
			}
			valid++
		case testTokenVolume:
			if volume.Secret == nil || volume.Secret.SecretName != "voice-mcp-test-token" {
				return "", false
			}
			valid++
		}
	}
	return sourceName, valid == 5
}

func voiceMCPBotImage(spec corev1.PodSpec) string {
	for _, container := range spec.Containers {
		if container.Name == "bot" {
			return container.Image
		}
	}
	return ""
}

func voiceMCPReady(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.PodIP == "" {
		return false
	}
	if _, err := netip.ParseAddr(pod.Status.PodIP); err != nil {
		return false
	}
	if _, ok := voiceMCPMounts(pod); !ok {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func voiceMCPScopeAt(ctx context.Context, reader client.Reader, target Target) (voiceMCPScope, error) {
	var scope voiceMCPScope
	if reader == nil || target.Namespace != voicemcppolicy.Namespace || target.Pod == "" || target.UID == "" || target.PolicyName == "" || target.PolicyUID == "" {
		return scope, fmt.Errorf("voice MCP target authority incomplete")
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: target.Pod}, pod); err != nil {
		return scope, err
	}
	if string(pod.UID) != target.UID || !voiceMCPReady(pod) || pod.Annotations["phorvex.ai/voice-mcp-policy-configmap"] != voicemcppolicy.ConfigMapName ||
		!voicemcppolicy.ValidSHA(pod.Annotations["phorvex.ai/voice-mcp-source-sha256"]) || pod.Annotations["phorvex.ai/voice-mcp-event-creator"] == "" {
		return scope, fmt.Errorf("voice MCP target Pod source, mount or readiness unbound")
	}
	dep, err := voiceMCPOwner(ctx, reader, pod)
	if err != nil {
		return scope, err
	}
	if voiceadmissionpolicy.HasWrapperAuthority(pod) {
		if _, err := voiceadmissionpolicy.VerifySource(ctx, reader, pod, dep); err != nil {
			return scope, err
		}
	}
	templateSource, templateOK := voiceMCPMounts(&corev1.Pod{Spec: dep.Spec.Template.Spec})
	if !templateOK || templateSource == "" || voiceMCPBotImage(dep.Spec.Template.Spec) != voiceMCPBotImage(pod.Spec) ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-policy-configmap"] != voicemcppolicy.ConfigMapName ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-source-configmap"] != templateSource ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-source-sha256"] != pod.Annotations["phorvex.ai/voice-mcp-source-sha256"] ||
		dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-event-creator"] != pod.Annotations["phorvex.ai/voice-mcp-event-creator"] {
		return scope, fmt.Errorf("voice MCP Deployment template source or MCP URL unbound")
	}
	pol, err := receiptAuthority(ctx, reader, operationReceipt{PolicyNamespace: target.Namespace, PolicyName: target.PolicyName, PolicyUID: target.PolicyUID,
		TargetName: target.Pod, TargetUID: target.UID, TargetLabels: pod.Labels}, model.ActionVoiceMCPToolPin)
	if err != nil {
		return scope, err
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) {
		return scope, fmt.Errorf("voice MCP Pod outside policy selector")
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voicemcppolicy.ConfigMapName}, cm); err != nil {
		return scope, err
	}
	if cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller ||
		cm.OwnerReferences[0].APIVersion != "apps/v1" || cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Name != dep.Name ||
		len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return scope, fmt.Errorf("voice MCP rule ConfigMap owner or data invalid")
	}
	rule, err := voicemcppolicy.Parse(cm.Data[voicemcppolicy.RuleKey])
	if err != nil || rule.DeploymentUID != string(dep.UID) || rule.PolicyUID != string(pol.UID) || rule.SourceSHA256 != pod.Annotations["phorvex.ai/voice-mcp-source-sha256"] {
		return scope, fmt.Errorf("voice MCP current rule identity invalid")
	}
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voiceMCPSecretName}, secret); err != nil {
		return scope, err
	}
	token := secret.Data["token"]
	if len(token) < 32 || len(token) > 256 {
		return scope, fmt.Errorf("voice MCP private readback token invalid")
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return scope, fmt.Errorf("voice MCP private readback token invalid")
		}
	}
	depSel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || depSel.Empty() || !depSel.Matches(labels.Set(pod.Labels)) {
		return scope, fmt.Errorf("voice MCP Deployment selector invalid")
	}
	list := &corev1.PodList{}
	if err := reader.List(ctx, list, client.InNamespace(target.Namespace), client.Limit(129)); err != nil {
		return scope, err
	}
	if list.Continue != "" || len(list.Items) == 0 || len(list.Items) > 128 {
		return scope, fmt.Errorf("voice MCP Pod inventory bound exceeded")
	}
	found := false
	for _, candidate := range list.Items {
		if candidate.DeletionTimestamp != nil {
			continue
		}
		owner, err := voiceMCPOwner(ctx, reader, &candidate)
		if err != nil {
			if depSel.Matches(labels.Set(candidate.Labels)) {
				return scope, fmt.Errorf("voice MCP labelled Pod owner chain invalid")
			}
			continue
		}
		if owner.UID != dep.UID {
			continue
		}
		if voiceadmissionpolicy.HasWrapperAuthority(&candidate) {
			if _, err := voiceadmissionpolicy.VerifySource(ctx, reader, &candidate, dep); err != nil {
				return scope, err
			}
		}
		sourceName, mounted := voiceMCPMounts(&candidate)
		if !mounted || sourceName != templateSource || !voiceMCPReady(&candidate) || !depSel.Matches(labels.Set(candidate.Labels)) || !sel.Matches(labels.Set(candidate.Labels)) ||
			candidate.Annotations["phorvex.ai/voice-mcp-policy-configmap"] != voicemcppolicy.ConfigMapName ||
			candidate.Annotations["phorvex.ai/voice-mcp-source-configmap"] != sourceName ||
			candidate.Annotations["phorvex.ai/voice-mcp-source-sha256"] != rule.SourceSHA256 ||
			candidate.Annotations["phorvex.ai/voice-mcp-event-creator"] != pod.Annotations["phorvex.ai/voice-mcp-event-creator"] {
			return scope, fmt.Errorf("voice MCP serving Pod scope incomplete")
		}
		source := &corev1.ConfigMap{}
		if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: sourceName}, source); err != nil {
			return scope, err
		}
		digest, err := voicemcppolicy.RuntimeSourceSHA(source)
		bundleDigest, bundleErr := voicemcppolicy.BundleSourceSHA(source)
		if err != nil || bundleErr != nil || digest != rule.SourceSHA256 || sourceName != "voice-memory-source-"+bundleDigest[:12] {
			return scope, fmt.Errorf("voice MCP runtime source identity changed")
		}
		if source.UID == "" || source.ResourceVersion == "" || len(source.OwnerReferences) != 1 ||
			source.OwnerReferences[0].Controller == nil || !*source.OwnerReferences[0].Controller ||
			source.OwnerReferences[0].APIVersion != "apps/v1" || source.OwnerReferences[0].Kind != "Deployment" ||
			source.OwnerReferences[0].Name != dep.Name || source.OwnerReferences[0].UID != dep.UID ||
			(scope.sourceName != "" && (sourceName != scope.sourceName || string(source.UID) != scope.sourceUID)) {
			return scope, fmt.Errorf("voice MCP runtime source ConfigMap identity changed")
		}
		scope.sourceName, scope.sourceUID = sourceName, string(source.UID)
		if candidate.UID == pod.UID {
			found = true
		}
		scope.pods = append(scope.pods, candidate)
	}
	if !found || len(scope.pods) == 0 {
		return scope, fmt.Errorf("voice MCP target absent from serving set")
	}
	scope.pod, scope.deployment, scope.policy, scope.cm, scope.rule, scope.secret = pod, dep, pol, cm, rule, append([]byte(nil), token...)
	return scope, nil
}

type voiceMCPState struct {
	Version              int    `json:"version"`
	PodUID               string `json:"podUID"`
	DeploymentUID        string `json:"deploymentUID"`
	PolicyUID            string `json:"policyUID"`
	SourceSHA256         string `json:"sourceSHA256"`
	RuleSHA256           string `json:"ruleSHA256"`
	Revision             uint64 `json:"revision"`
	OperationID          string `json:"operationId"`
	EntryCount           int    `json:"entryCount"`
	Ready                bool   `json:"ready"`
	GoodDescriptorSHA256 string `json:"goodDescriptorSHA256"`
}

func voiceMCPReadback(ctx context.Context, scope voiceMCPScope, rule voicemcppolicy.Rule, transport http.RoundTripper) error {
	if len(scope.pods) == 0 || !rule.Valid() {
		return fmt.Errorf("voice MCP private readback scope empty or rule invalid")
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	}
	httpClient := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, pod := range scope.pods {
		url := "http://" + net.JoinHostPort(pod.Status.PodIP, "8080") + voicemcppolicy.StatePath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+string(scope.secret))
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("voice MCP private readback unavailable for Pod UID %s: %w", pod.UID, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		if readErr != nil || len(body) > 4096 || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
			return fmt.Errorf("voice MCP private readback unready for Pod UID %s", pod.UID)
		}
		if outputPolicyExactObject(body, "version", "podUID", "deploymentUID", "policyUID", "sourceSHA256", "ruleSHA256", "revision", "operationId", "entryCount", "ready", "goodDescriptorSHA256") != nil {
			return fmt.Errorf("voice MCP private readback shape invalid")
		}
		var state voiceMCPState
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if dec.Decode(&state) != nil || !state.Ready || state.Version != 1 || state.PodUID != string(pod.UID) || state.DeploymentUID != rule.DeploymentUID ||
			state.PolicyUID != rule.PolicyUID || state.SourceSHA256 != rule.SourceSHA256 || state.RuleSHA256 != rule.SHA256() || state.Revision != rule.Revision ||
			state.OperationID != rule.OperationID || state.EntryCount != len(rule.Entries) || state.GoodDescriptorSHA256 != voicemcppolicy.StoreDirectoryGoodSHA256 {
			return fmt.Errorf("voice MCP private readback identity or rule mismatch for Pod UID %s", pod.UID)
		}
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("voice MCP private readback trailing data")
		}
	}
	return nil
}

func voiceMCPJournalName(deploymentUID string, revision uint64) string {
	h := sha256.Sum256([]byte(deploymentUID))
	return "phorvex-voice-mcp-" + hex.EncodeToString(h[:16]) + "-" + strconv.FormatUint(revision, 10)
}

type voiceMCPReceipt struct {
	Version             int                 `json:"version"`
	Phase               string              `json:"phase"`
	PolicyName          string              `json:"policyName"`
	PolicyUID           string              `json:"policyUID"`
	PolicyGeneration    int64               `json:"policyGeneration"`
	DeploymentUID       string              `json:"deploymentUID"`
	TargetName          string              `json:"targetName"`
	TargetPodUID        string              `json:"targetPodUID"`
	EventName           string              `json:"eventName"`
	EventUID            string              `json:"eventUID"`
	RunSHA256           string              `json:"runSHA256"`
	CreatorIdentity     string              `json:"creatorIdentity"`
	TickID              string              `json:"tickId"`
	SelectionDecisionID string              `json:"selectionDecisionId"`
	ConfigMapUID        string              `json:"configMapUID"`
	SourceConfigMapUID  string              `json:"sourceConfigMapUID"`
	MCPServiceName      string              `json:"mcpServiceName"`
	MCPServiceUID       string              `json:"mcpServiceUID"`
	MCPPodName          string              `json:"mcpPodName"`
	MCPPodUID           string              `json:"mcpPodUID"`
	MCPDeploymentUID    string              `json:"mcpDeploymentUID"`
	MCPConfigMapUID     string              `json:"mcpConfigMapUID"`
	MCPSourceSHA256     string              `json:"mcpSourceSHA256"`
	MCPApprovedImage    string              `json:"mcpApprovedImage"`
	ObservedSHA256      string              `json:"observedDescriptorSHA256"`
	ToolName            string              `json:"toolName"`
	Prior               voicemcppolicy.Rule `json:"prior"`
	Desired             voicemcppolicy.Rule `json:"desired"`
	OperationID         string              `json:"operationId"`
}

type voiceMCPEventAssertion struct {
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

func voiceMCPEvent(ctx context.Context, reader client.Reader, req Request, observation *model.VoiceMCPObservation, scope voiceMCPScope) error {
	event := &amtdv1beta1.SecurityEvent{}
	if err := reader.Get(ctx, client.ObjectKey{Name: observation.EventName}, event); err != nil {
		return err
	}
	if string(event.UID) != observation.EventUID || event.DeletionTimestamp != nil || event.Annotations["phorvex.ai/creator-identity"] != observation.CreatorIdentity ||
		scope.pod.Annotations["phorvex.ai/voice-mcp-event-creator"] != observation.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != observation.TargetPodUID || event.Spec.Rule.Type != model.AttackVectorVoiceMCP ||
		event.Spec.Rule.Source != "redteam" || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.CreationTimestamp.IsZero() || time.Since(event.CreationTimestamp.Time) < 0 || time.Since(event.CreationTimestamp.Time) >= time.Minute {
		return fmt.Errorf("voice MCP event identity or freshness changed")
	}
	raw := event.Annotations[voiceMCPEventAnnotation]
	if len(raw) == 0 || len(raw) > 4096 || outputPolicyExactObject([]byte(raw), "version", "scenarioId", "runSHA256", "toolName",
		"observedDescriptorSHA256", "goodDescriptorSHA256", "deploymentUID", "podUID", "sourceSHA256", "mcpDeploymentUID", "mcpPodUID",
		"mcpServiceUID", "mcpConfigMapUID", "mcpSourceSHA256", "policyName", "policyUID", "policyGeneration", "observedAt",
		"evidenceSource", "mcpFetchObserved", "voiceBehaviorObserved") != nil {
		return fmt.Errorf("voice MCP event assertion invalid")
	}
	var assertion voiceMCPEventAssertion
	if json.Unmarshal([]byte(raw), &assertion) != nil || assertion.Version != 1 || assertion.ScenarioID != "ai2-mcp-tool-poisoning" ||
		assertion.ScenarioID != observation.ScenarioID || assertion.RunSHA256 != observation.RunSHA256 ||
		assertion.ToolName != voicemcppolicy.StoreDirectory || assertion.ToolName != observation.ToolName ||
		assertion.GoodDescriptorSHA256 != voicemcppolicy.StoreDirectoryGoodSHA256 || assertion.GoodDescriptorSHA256 != observation.GoodDescriptorSHA256 ||
		assertion.ObservedDescriptorSHA256 != observation.ObservedDescriptorSHA256 || assertion.ObservedDescriptorSHA256 == assertion.GoodDescriptorSHA256 ||
		assertion.DeploymentUID != observation.DeploymentUID || assertion.PodUID != observation.TargetPodUID ||
		assertion.SourceSHA256 != observation.SourceSHA256 || assertion.MCPDeploymentUID != observation.MCPDeploymentUID ||
		assertion.MCPPodUID != observation.MCPPodUID || assertion.MCPServiceUID != observation.MCPServiceUID ||
		assertion.MCPConfigMapUID != observation.MCPConfigMapUID || assertion.MCPSourceSHA256 != observation.MCPSourceSHA256 ||
		assertion.PolicyName != req.PolicyName || assertion.PolicyUID != req.PolicyUID || assertion.PolicyGeneration != req.PolicyGeneration ||
		assertion.EvidenceSource != "TEST_INJECTED" || !assertion.MCPFetchObserved || !assertion.VoiceBehaviorObserved ||
		assertion.ObservedAt.IsZero() || !assertion.ObservedAt.Equal(observation.ObservedAt) || assertion.ObservedAt.After(time.Now()) ||
		assertion.ObservedAt.After(event.CreationTimestamp.Time.Add(time.Second)) || event.CreationTimestamp.Time.Sub(assertion.ObservedAt) > time.Minute {
		return fmt.Errorf("voice MCP event payload changed")
	}
	return nil
}

func voiceMCPOperationID(req Request, o *model.VoiceMCPObservation) string {
	h := sha256.Sum256([]byte("phorvex-voice-mcp-v1\x00" + req.PolicyUID + "\x00" + o.DeploymentUID + "\x00" + o.TargetPodUID + "\x00" +
		o.EventUID + "\x00" + o.RunSHA256 + "\x00" + o.ToolName + "\x00" + o.MCPServiceUID + "\x00" + o.MCPPodUID + "\x00" +
		o.MCPDeploymentUID + "\x00" + o.MCPConfigMapUID + "\x00" + o.MCPSourceSHA256 + "\x00" + req.TickID + "\x00" + req.OperationID))
	return hex.EncodeToString(h[:])
}

func voiceMCPJournalGet(ctx context.Context, ec EnactCtx, name string) (*corev1.ConfigMap, voiceMCPReceipt, error) {
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}, cm); err != nil {
		return nil, voiceMCPReceipt{}, err
	}
	var r voiceMCPReceipt
	if cm.Labels[voiceMCPJournalLabel] != "v1" || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
		len(cm.Data) != 1 || len(cm.Data["receipt.json"]) == 0 || len(cm.Data["receipt.json"]) > 150000 ||
		json.Unmarshal([]byte(cm.Data["receipt.json"]), &r) != nil || r.Version != 1 ||
		(r.Phase != "prepared" && r.Phase != "terminal-full") || !r.Prior.Valid() || !r.Desired.Valid() ||
		r.Desired.Revision != r.Prior.Revision+1 || r.Desired.OperationID != r.OperationID || !voicemcppolicy.ValidSHA(r.OperationID) ||
		r.DeploymentUID != r.Prior.DeploymentUID || r.PolicyUID != r.Prior.PolicyUID || r.TargetName == "" || r.TargetPodUID == "" ||
		r.EventName == "" || r.EventUID == "" || !voicemcppolicy.ValidSHA(r.RunSHA256) || r.CreatorIdentity == "" || r.TickID == "" || r.SelectionDecisionID == "" ||
		r.SourceConfigMapUID == "" || r.ConfigMapUID == "" || r.PolicyName == "" || r.PolicyGeneration <= 0 ||
		r.MCPServiceName != voicemcppolicy.MCPServiceName || !voicemcppolicy.ValidUID(r.MCPServiceUID) || r.MCPPodName == "" || !voicemcppolicy.ValidUID(r.MCPPodUID) ||
		!voicemcppolicy.ValidUID(r.MCPDeploymentUID) || !voicemcppolicy.ValidUID(r.MCPConfigMapUID) ||
		!voicemcppolicy.ValidSHA(r.MCPSourceSHA256) || !voicemcppolicy.ValidApprovedImage(r.MCPApprovedImage) || !voicemcppolicy.ValidSHA(r.ObservedSHA256) ||
		r.Prior.SourceSHA256 != r.Desired.SourceSHA256 || r.Prior.PolicyUID != r.Desired.PolicyUID || r.Prior.DeploymentUID != r.Desired.DeploymentUID ||
		cm.Name != voiceMCPJournalName(r.DeploymentUID, r.Desired.Revision) || len(r.TickID) > 253 || len(r.SelectionDecisionID) > 253 {
		return nil, voiceMCPReceipt{}, fmt.Errorf("voice MCP journal invalid")
	}
	canonical, _ := json.Marshal(r)
	if cm.Data["receipt.json"] != string(canonical) || r.OperationID != voiceMCPOperationID(Request{PolicyUID: r.PolicyUID, TickID: r.TickID,
		OperationID: r.SelectionDecisionID}, &model.VoiceMCPObservation{DeploymentUID: r.DeploymentUID, TargetPodUID: r.TargetPodUID,
		EventUID: r.EventUID, RunSHA256: r.RunSHA256, ToolName: r.ToolName, MCPServiceUID: r.MCPServiceUID, MCPPodUID: r.MCPPodUID,
		MCPDeploymentUID: r.MCPDeploymentUID, MCPConfigMapUID: r.MCPConfigMapUID, MCPSourceSHA256: r.MCPSourceSHA256}) {
		return nil, voiceMCPReceipt{}, fmt.Errorf("voice MCP journal intent invalid")
	}
	rebuilt, err := voicemcppolicy.Append(r.Prior, r.ToolName, r.OperationID)
	if err != nil || rebuilt.SHA256() != r.Desired.SHA256() || len(r.Desired.Entries) != len(r.Prior.Entries)+1 {
		return nil, voiceMCPReceipt{}, fmt.Errorf("voice MCP journal erased prior entry")
	}
	return cm, r, nil
}

func voiceMCPCapability(ctx context.Context, reader client.Reader, journalNS string, target Target, transport http.RoundTripper, approvedImage string) (bool, string) {
	if journalNS == "" {
		return false, "voice-mcp-journal-unavailable"
	}
	if !voicemcppolicy.ValidApprovedImage(approvedImage) {
		return false, "voice-mcp-approved-image-unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	scope, err := voiceMCPScopeAt(probe, reader, target)
	if err != nil {
		return false, "voice-mcp-scope-unavailable: " + err.Error()
	}
	if len(scope.rule.Entries) >= voicemcppolicy.MaxEntries {
		return false, "voice-mcp-pins-full"
	}
	ec := EnactCtx{Reader: reader, JournalNamespace: journalNS}
	if scope.rule.Revision > 0 {
		_, previous, err := voiceMCPJournalGet(probe, ec, voiceMCPJournalName(string(scope.deployment.UID), scope.rule.Revision))
		if err != nil || previous.Phase != "terminal-full" || previous.Desired.SHA256() != scope.rule.SHA256() {
			return false, "voice-mcp-prior-operation-unverified"
		}
	}
	if _, _, err := voiceMCPJournalGet(probe, ec, voiceMCPJournalName(string(scope.deployment.UID), scope.rule.Revision+1)); err == nil {
		return false, "voice-mcp-operation-pending"
	} else if !apierrors.IsNotFound(err) {
		return false, "voice-mcp-journal-read-failed"
	}
	if err := voiceMCPReadback(probe, scope, scope.rule, transport); err != nil {
		return false, "voice-mcp-app-readback-unavailable"
	}
	return true, ""
}

func voiceMCPPodSetEqual(a, b []corev1.Pod) bool {
	if len(a) != len(b) {
		return false
	}
	uids := make(map[string]bool, len(a))
	for _, pod := range a {
		uids[string(pod.UID)] = true
	}
	for _, pod := range b {
		if !uids[string(pod.UID)] {
			return false
		}
	}
	return true
}

func voiceMCPResume(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, receipt voiceMCPReceipt) (HandlerResult, error) {
	if ec.VoiceMCPApprovedImage != receipt.MCPApprovedImage || !voicemcppolicy.ValidApprovedImage(ec.VoiceMCPApprovedImage) {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice MCP approved image changed")
	}
	target := Target{Namespace: voicemcppolicy.Namespace, Pod: receipt.TargetName, UID: receipt.TargetPodUID, PolicyName: receipt.PolicyName, PolicyUID: receipt.PolicyUID}
	scope, err := voiceMCPScopeAt(ctx, ec.Reader, target)
	if err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	if string(scope.deployment.UID) != receipt.DeploymentUID || string(scope.cm.UID) != receipt.ConfigMapUID || scope.sourceUID != receipt.SourceConfigMapUID ||
		scope.policy.Generation != receipt.PolicyGeneration || scope.rule.SourceSHA256 != receipt.Prior.SourceSHA256 {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice MCP recovery authority changed")
	}
	sourcePins := voicemcppolicy.SourcePins{DeploymentUID: receipt.MCPDeploymentUID, PodUID: receipt.MCPPodUID,
		ServiceUID: receipt.MCPServiceUID, ConfigMapUID: receipt.MCPConfigMapUID, SourceSHA256: receipt.MCPSourceSHA256, ApprovedImage: receipt.MCPApprovedImage}
	mcpSource, err := voicemcppolicy.CurrentSource(ctx, ec.Reader, sourcePins)
	if err != nil || mcpSource.PodName != receipt.MCPPodName {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice MCP recovery source changed: %v", err)
	}
	if scope.rule.SHA256() == receipt.Prior.SHA256() {
		if err := voiceMCPReadback(ctx, scope, receipt.Prior, ec.VoiceMCPTransport); err != nil {
			return HandlerResult{MutationKind: "partial"}, err
		}
		copy := scope.cm.DeepCopy()
		copy.Data[voicemcppolicy.RuleKey] = string(receipt.Desired.Bytes())
		if err := ec.Client.Update(ctx, copy); err != nil {
			return HandlerResult{MutationKind: "partial", Note: "voice MCP prepared operation requires recovery"}, err
		}
	} else if scope.rule.SHA256() != receipt.Desired.SHA256() {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice MCP rule superseded prepared operation")
	}
	deadline, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		current, scopeErr := voiceMCPScopeAt(deadline, ec.Reader, target)
		if scopeErr == nil {
			switch current.rule.SHA256() {
			case receipt.Desired.SHA256():
				if !voiceMCPPodSetEqual(scope.pods, current.pods) {
					scopeErr = fmt.Errorf("voice MCP serving Pod set changed")
				} else {
					scopeErr = voiceMCPReadback(deadline, current, receipt.Desired, ec.VoiceMCPTransport)
					if scopeErr == nil {
						post, postErr := voiceMCPScopeAt(deadline, ec.Reader, target)
						if postErr != nil || !voiceMCPPodSetEqual(current.pods, post.pods) || post.rule.SHA256() != receipt.Desired.SHA256() || post.sourceUID != receipt.SourceConfigMapUID {
							scopeErr = fmt.Errorf("voice MCP serving scope changed across readback: %v", postErr)
						} else if source, sourceErr := voicemcppolicy.CurrentSource(deadline, ec.Reader, sourcePins); sourceErr != nil || source.PodName != receipt.MCPPodName {
							scopeErr = fmt.Errorf("voice MCP source changed across readback: %v", sourceErr)
						}
					}
				}
			case receipt.Prior.SHA256():
				scopeErr = fmt.Errorf("voice MCP desired rule not yet observed")
			default:
				return HandlerResult{MutationKind: "partial", Note: "voice MCP prepared operation superseded after write"}, fmt.Errorf("voice MCP rule superseded prepared operation")
			}
		}
		if scopeErr == nil {
			if receipt.Phase == "prepared" {
				copy := journal.DeepCopy()
				receipt.Phase = "terminal-full"
				encoded, _ := json.Marshal(receipt)
				copy.Data["receipt.json"] = string(encoded)
				if err := ec.Client.Update(ctx, copy); err != nil {
					return HandlerResult{MutationKind: "partial", Note: "voice MCP rule observed but journal terminal write failed"}, err
				}
				return HandlerResult{ObjectsTouched: []string{voicemcppolicy.Namespace + "/" + voicemcppolicy.ConfigMapName}, MutationKind: "forward-only", Emitted: true,
					Note: "voice MCP reviewed descriptor pin confirmed on all serving Pods; prior answer not undone"}, nil
			}
			return HandlerResult{NoEffect: NoEffectReconciled, MutationKind: "none", ObjectsTouched: []string{voicemcppolicy.Namespace + "/" + voicemcppolicy.ConfigMapName},
				Note: "previous Voice MCP descriptor pin remains confirmed; no new effect credited"}, nil
		}
		select {
		case <-deadline.Done():
			return HandlerResult{MutationKind: "partial", Note: "voice MCP rule updated; complete per-Pod projection unverified"}, fmt.Errorf("voice MCP projection readback timed out: %w", scopeErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func voiceMCPSelectionMatches(recorded voiceMCPReceipt, req Request, observation *model.VoiceMCPObservation, operationID string) bool {
	return observation != nil && recorded.OperationID == operationID && recorded.PolicyName == req.PolicyName && recorded.PolicyUID == req.PolicyUID &&
		recorded.PolicyGeneration == req.PolicyGeneration && recorded.DeploymentUID == observation.DeploymentUID &&
		recorded.TargetName == req.Pod && recorded.TargetPodUID == req.TargetUID && recorded.EventName == observation.EventName &&
		recorded.EventUID == observation.EventUID && recorded.RunSHA256 == observation.RunSHA256 &&
		recorded.CreatorIdentity == observation.CreatorIdentity && recorded.TickID == req.TickID &&
		recorded.SelectionDecisionID == req.OperationID && recorded.ConfigMapUID == observation.ConfigMapUID &&
		recorded.SourceConfigMapUID == observation.SourceConfigMapUID && recorded.MCPServiceName == observation.MCPServiceName &&
		recorded.MCPServiceUID == observation.MCPServiceUID && recorded.MCPPodName == observation.MCPPodName &&
		recorded.MCPPodUID == observation.MCPPodUID && recorded.MCPDeploymentUID == observation.MCPDeploymentUID &&
		recorded.MCPConfigMapUID == observation.MCPConfigMapUID && recorded.MCPSourceSHA256 == observation.MCPSourceSHA256 &&
		recorded.ObservedSHA256 == observation.ObservedDescriptorSHA256 && recorded.ToolName == observation.ToolName &&
		recorded.Prior.SHA256() == observation.RuleSHA256 && recorded.Desired.OperationID == operationID
}

type voiceMCPHandler struct{}

func (voiceMCPHandler) Name() string { return string(model.ActionVoiceMCPToolPin) }

func (voiceMCPHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	o := req.VoiceMCPObservation
	if req.Action != model.ActionVoiceMCPToolPin || ec.Client == nil || ec.Reader == nil || ec.JournalNamespace == "" ||
		o == nil || !voicemcppolicy.ValidApprovedImage(ec.VoiceMCPApprovedImage) || req.TickID == "" || req.OperationID == "" || len(req.TickID) > 253 || len(req.OperationID) > 253 ||
		req.Namespace != voicemcppolicy.Namespace || o.TargetPodUID != req.TargetUID || o.PolicyName != req.PolicyName ||
		o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration || o.ScenarioID != "ai2-mcp-tool-poisoning" ||
		!voicemcppolicy.ValidSHA(o.RunSHA256) || o.ToolName != voicemcppolicy.StoreDirectory ||
		o.GoodDescriptorSHA256 != voicemcppolicy.StoreDirectoryGoodSHA256 || !voicemcppolicy.ValidSHA(o.ObservedDescriptorSHA256) ||
		o.ObservedDescriptorSHA256 == o.GoodDescriptorSHA256 || o.MCPServiceName != voicemcppolicy.MCPServiceName ||
		!voicemcppolicy.ValidUID(o.MCPDeploymentUID) || !voicemcppolicy.ValidUID(o.MCPPodUID) ||
		!voicemcppolicy.ValidUID(o.MCPServiceUID) || !voicemcppolicy.ValidUID(o.MCPConfigMapUID) ||
		!voicemcppolicy.ValidSHA(o.MCPSourceSHA256) {
		return HandlerResult{}, fmt.Errorf("voice MCP selection authority incomplete")
	}
	target := Target{Namespace: req.Namespace, Pod: req.Pod, UID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}
	scope, err := voiceMCPScopeAt(ctx, ec.Reader, target)
	if err != nil {
		return HandlerResult{}, err
	}
	operationID := voiceMCPOperationID(req, o)
	name := voiceMCPJournalName(o.DeploymentUID, o.SelectedRevision+1)
	if journal, recorded, err := voiceMCPJournalGet(ctx, ec, name); err == nil {
		if !voiceMCPSelectionMatches(recorded, req, o, operationID) {
			return HandlerResult{}, fmt.Errorf("voice MCP journal occupied by another selection")
		}
		return voiceMCPResume(ctx, ec, journal, recorded)
	} else if !apierrors.IsNotFound(err) {
		return HandlerResult{}, err
	}
	if string(scope.deployment.UID) != o.DeploymentUID || string(scope.cm.UID) != o.ConfigMapUID ||
		scope.cm.ResourceVersion != o.ConfigMapResourceVersion || scope.sourceUID != o.SourceConfigMapUID ||
		scope.rule.Revision != o.SelectedRevision || scope.rule.SHA256() != o.RuleSHA256 || scope.rule.SourceSHA256 != o.SourceSHA256 ||
		scope.policy.Generation != o.PolicyGeneration {
		return HandlerResult{}, fmt.Errorf("voice MCP selected source or rule changed")
	}
	sourcePins := voicemcppolicy.SourcePins{DeploymentUID: o.MCPDeploymentUID, PodUID: o.MCPPodUID,
		ServiceUID: o.MCPServiceUID, ConfigMapUID: o.MCPConfigMapUID, SourceSHA256: o.MCPSourceSHA256, ApprovedImage: ec.VoiceMCPApprovedImage}
	mcpSource, err := voicemcppolicy.CurrentSource(ctx, ec.Reader, sourcePins)
	if err != nil || mcpSource.PodName != o.MCPPodName {
		return HandlerResult{}, fmt.Errorf("voice MCP source changed: %v", err)
	}
	if err := voiceMCPEvent(ctx, ec.Reader, req, o, scope); err != nil {
		return HandlerResult{}, err
	}
	for _, entry := range scope.rule.Entries {
		if entry.ToolName == o.ToolName {
			return HandlerResult{}, fmt.Errorf("voice MCP tool already pinned")
		}
	}
	if scope.rule.Revision > 0 {
		_, previous, err := voiceMCPJournalGet(ctx, ec, voiceMCPJournalName(o.DeploymentUID, scope.rule.Revision))
		if err != nil || previous.Phase != "terminal-full" || previous.Desired.SHA256() != scope.rule.SHA256() {
			return HandlerResult{}, fmt.Errorf("voice MCP prior operation unverified")
		}
	}
	if err := voiceMCPReadback(ctx, scope, scope.rule, ec.VoiceMCPTransport); err != nil {
		return HandlerResult{}, err
	}
	desired, err := voicemcppolicy.Append(scope.rule, o.ToolName, operationID)
	if err != nil {
		return HandlerResult{}, err
	}
	receipt := voiceMCPReceipt{Version: 1, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration,
		DeploymentUID: o.DeploymentUID, TargetName: req.Pod, TargetPodUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID,
		RunSHA256: o.RunSHA256, CreatorIdentity: o.CreatorIdentity, TickID: req.TickID, SelectionDecisionID: req.OperationID,
		ConfigMapUID: o.ConfigMapUID, SourceConfigMapUID: o.SourceConfigMapUID, MCPServiceName: o.MCPServiceName,
		MCPServiceUID: o.MCPServiceUID, MCPPodName: o.MCPPodName, MCPPodUID: o.MCPPodUID, MCPDeploymentUID: o.MCPDeploymentUID,
		MCPConfigMapUID: o.MCPConfigMapUID, MCPSourceSHA256: o.MCPSourceSHA256, MCPApprovedImage: ec.VoiceMCPApprovedImage, ObservedSHA256: o.ObservedDescriptorSHA256,
		ToolName: o.ToolName, Prior: scope.rule, Desired: desired, OperationID: operationID}
	encoded, _ := json.Marshal(receipt)
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ec.JournalNamespace,
		Labels: map[string]string{voiceMCPJournalLabel: "v1"}}, Data: map[string]string{"receipt.json": string(encoded)}}
	if err := ec.Client.Create(ctx, journal); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return HandlerResult{}, err
		}
		journal, existing, readErr := voiceMCPJournalGet(ctx, ec, name)
		if readErr != nil || existing.Phase != "prepared" || !voiceMCPSelectionMatches(existing, req, o, operationID) ||
			existing.Prior.SHA256() != scope.rule.SHA256() || existing.Desired.SHA256() != desired.SHA256() {
			return HandlerResult{}, fmt.Errorf("voice MCP journal occupied by another selection")
		}
		return voiceMCPResume(ctx, ec, journal, existing)
	}
	return voiceMCPResume(ctx, ec, journal, receipt)
}

func init() { HandlerRegistry.Register(voiceMCPHandler{}) }

func recoverVoiceMCPOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	list := &corev1.ConfigMapList{}
	if err := ec.Reader.List(ctx, list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{voiceMCPJournalLabel: "v1"}, client.Limit(101)); err != nil {
		return nil, err
	}
	if list.Continue != "" || len(list.Items) > 100 {
		return nil, fmt.Errorf("voice MCP journal inventory exceeded recovery bound")
	}
	events := make([]RecoveryEvent, 0, len(list.Items))
	for i := range list.Items {
		journal, receipt, err := voiceMCPJournalGet(ctx, ec, list.Items[i].Name)
		ev := RecoveryEvent{Receipt: list.Items[i].Name, Kind: string(model.ActionVoiceMCPToolPin), Outcome: "refused"}
		if err != nil {
			ev.Err = err
			events = append(events, ev)
			continue
		}
		ev.Phase, ev.PolicyNamespace, ev.PolicyName, ev.PolicyUID = receipt.Phase, voicemcppolicy.Namespace, receipt.PolicyName, receipt.PolicyUID
		ev.TargetName, ev.TargetUID = receipt.TargetName, receipt.TargetPodUID
		if policy, authorityErr := receiptAuthority(ctx, ec.Reader, operationReceipt{PolicyNamespace: voicemcppolicy.Namespace,
			PolicyName: receipt.PolicyName, PolicyUID: receipt.PolicyUID, TargetName: receipt.TargetName, TargetUID: receipt.TargetPodUID}, model.ActionVoiceMCPToolPin); authorityErr == nil {
			ev.Tenant = policy.Spec.Tenant
			if ev.Tenant == "" {
				ev.Tenant = voicemcppolicy.Namespace
			}
		}
		if allow != nil && !allow(model.ActionVoiceMCPToolPin) {
			ev.Err = fmt.Errorf("voice MCP recovery routed away from native")
			events = append(events, ev)
			continue
		}
		if receipt.Phase == "terminal-full" {
			ev.Outcome = "confirmed"
			ev.Effect = "previously confirmed per-Pod Voice MCP descriptor pin"
			events = append(events, ev)
			continue
		}
		_, ev.Err = voiceMCPResume(ctx, ec, journal, receipt)
		if ev.Err == nil {
			ev.Outcome = "confirmed"
			ev.Effect = "Voice MCP descriptor pin confirmed on current serving Pods"
		} else {
			ev.Outcome = "partial"
		}
		events = append(events, ev)
	}
	return events, nil
}
