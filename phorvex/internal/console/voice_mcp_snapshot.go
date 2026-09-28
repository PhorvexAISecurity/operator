package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/internal/voicemcppolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	voiceMCPScenario     = "ai2-mcp-tool-poisoning"
	voiceMCPAction       = "voice-mcp-tool-pin"
	voiceMCPPolicyName   = "voice-defense"
	voiceMCPRoute        = "/api/voice/mcp/live/fire"
	voiceMCPProfilePath  = "/etc/phorvex-voice-mcp/profile.json"
	voiceMCPRuleCM       = "voice-mcp-tool-policy"
	voiceMCPGoodStoreSHA = "a4b965102419d4a81c4fd23cb3c93891f9932b8560b18bcd17f48aea81a337c8"
	voiceMCPURL          = voicemcppolicy.InstalledMCPURL
)

func voiceMCPBotRoute(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, container := range pod.Spec.Containers {
		if container.Name != "bot" {
			continue
		}
		count := 0
		for _, env := range container.Env {
			if env.Name == "MCP_URL" {
				if env.ValueFrom != nil || env.Value != voiceMCPURL {
					return false
				}
				count++
			}
		}
		return count == 1
	}
	return false
}

func voiceMCPBotMounts(pod *corev1.Pod, sourceName, mcpSourceSHA string) bool {
	if pod == nil {
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
	envWant := map[string]string{"VOICE_MCP_POLICY_REQUIRED": "true", "VOICE_MCP_TEST_ENABLED": "true",
		"VOICE_MCP_SERVER_SOURCE_SHA256": mcpSourceSHA}
	envSeen := map[string]bool{}
	for _, env := range bot.Env {
		if wantValue, ok := envWant[env.Name]; ok {
			if envSeen[env.Name] || env.ValueFrom != nil || env.Value != wantValue {
				return false
			}
			envSeen[env.Name] = true
		}
	}
	if len(envSeen) != len(envWant) {
		return false
	}
	want := map[string]string{"/app/bot.py": "voice-memory-source", "/app/voice_memory_policy.py": "voice-memory-source",
		"/app/voice_output_policy.py": "voice-memory-source", "/app/voice_mcp_policy.py": "voice-memory-source",
		"/etc/phorvex/voice-mcp-tool-policy":    "voice-mcp-rule",
		"/etc/phorvex/voice-mcp-test-token":     "voice-mcp-test-token",
		"/etc/phorvex/voice-memory-state-token": "voice-memory-token"}
	seen := map[string]bool{}
	for _, mount := range bot.VolumeMounts {
		if _, ok := want[mount.MountPath]; ok {
			if seen[mount.MountPath] || mount.Name != want[mount.MountPath] || !mount.ReadOnly {
				return false
			}
			if strings.HasPrefix(mount.MountPath, "/app/") && mount.SubPath != strings.TrimPrefix(mount.MountPath, "/app/") {
				return false
			}
			if !strings.HasPrefix(mount.MountPath, "/app/") && mount.SubPath != "" {
				return false
			}
			seen[mount.MountPath] = true
		}
	}
	if len(seen) != len(want) {
		return false
	}
	volumes := map[string]corev1.Volume{}
	for _, volume := range pod.Spec.Volumes {
		if _, exists := volumes[volume.Name]; exists {
			return false
		}
		volumes[volume.Name] = volume
	}
	source := volumes["voice-memory-source"]
	rule := volumes["voice-mcp-rule"]
	token := volumes["voice-mcp-test-token"]
	stateToken := volumes["voice-memory-token"]
	return source.ConfigMap != nil && source.ConfigMap.Name == sourceName &&
		rule.ConfigMap != nil && rule.ConfigMap.Name == voiceMCPRuleCM &&
		token.Secret != nil && token.Secret.SecretName == "voice-mcp-test-token" &&
		stateToken.Secret != nil && stateToken.Secret.SecretName == "voice-memory-state-token"
}

func voiceMCPServerMounts(pod *corev1.Pod, sourceName string) bool {
	if pod == nil {
		return false
	}
	var server *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "mcp-server" {
			server = &pod.Spec.Containers[i]
		}
	}
	if server == nil {
		return false
	}
	sourceMount, tokenMount := 0, 0
	for _, mount := range server.VolumeMounts {
		if mount.MountPath == "/app/server.py" {
			if mount.Name != "voice-mcp-source" || mount.SubPath != "server.py" || !mount.ReadOnly {
				return false
			}
			sourceMount++
		}
		if mount.MountPath == "/etc/phorvex/voice-mcp-test-token" {
			if mount.Name != "voice-mcp-test-token" || mount.SubPath != "" || !mount.ReadOnly {
				return false
			}
			tokenMount++
		}
	}
	sourceVol, tokenVol := 0, 0
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == "voice-mcp-source" && volume.ConfigMap != nil && volume.ConfigMap.Name == sourceName {
			sourceVol++
		}
		if volume.Name == "voice-mcp-test-token" && volume.Secret != nil && volume.Secret.SecretName == "voice-mcp-test-token" {
			tokenVol++
		}
	}
	enabled := 0
	for _, env := range server.Env {
		if env.Name == "VOICE_MCP_TEST_ENABLED" {
			if env.ValueFrom != nil || env.Value != "true" {
				return false
			}
			enabled++
		}
	}
	return sourceMount == 1 && tokenMount == 1 && sourceVol == 1 && tokenVol == 1 && enabled == 1
}

type voiceMCPProfile struct {
	Version               int    `json:"version"`
	SourceSHA256          string `json:"sourceSHA256"`
	SourceConfigMapSHA256 string `json:"sourceConfigMapSHA256"`
	MCPSourceSHA256       string `json:"mcpSourceSHA256"`
	MCPImage              string `json:"mcpImage"`
	ProbeSHA256           string `json:"probeSHA256"`
	AttackClipSHA256      string `json:"attackClipSHA256"`
	BenignClipSHA256      string `json:"benignClipSHA256"`
	GoodDescriptorSHA256  string `json:"goodDescriptorSHA256"`
	PolicyName            string `json:"policyName"`
	EventCreator          string `json:"eventCreator"`
	AuditSourceIdentity   string `json:"auditSourceIdentity"`
	MaxRunSeconds         int    `json:"maxRunSeconds"`
}

func parseVoiceMCPProfile(raw []byte) (voiceMCPProfile, error) {
	var p voiceMCPProfile
	if len(raw) == 0 || len(raw) > 4096 {
		return p, errors.New("MCP profile size invalid")
	}
	allowed := map[string]bool{"version": true, "sourceSHA256": true, "sourceConfigMapSHA256": true, "mcpSourceSHA256": true, "mcpImage": true, "probeSHA256": true,
		"attackClipSHA256": true, "benignClipSHA256": true, "goodDescriptorSHA256": true, "policyName": true,
		"eventCreator": true, "auditSourceIdentity": true, "maxRunSeconds": true}
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return p, errors.New("MCP profile object required")
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, e := dec.Token()
		key, ok := keyToken.(string)
		if e != nil || !ok || !allowed[key] || seen[key] {
			return p, errors.New("MCP profile key invalid or duplicate")
		}
		seen[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return p, errors.New("MCP profile value invalid")
		}
	}
	end, e := dec.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return p, errors.New("MCP profile fields incomplete")
	}
	if _, e = dec.Token(); e != io.EOF {
		return p, errors.New("MCP profile trailing content")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || p.Version != 1 || !staticSHA256.MatchString(p.SourceSHA256) || !staticSHA256.MatchString(p.SourceConfigMapSHA256) ||
		!staticSHA256.MatchString(p.MCPSourceSHA256) || p.ProbeSHA256 != voiceMCPProbeSHA ||
		strings.Count(p.MCPImage, "@sha256:") != 1 || p.MCPImage[0] == '@' ||
		!staticSHA256.MatchString(p.MCPImage[strings.LastIndex(p.MCPImage, "@sha256:")+8:]) ||
		p.AttackClipSHA256 != voiceMCPAttackAudioSHA || p.BenignClipSHA256 != voiceMCPBenignAudioSHA ||
		p.GoodDescriptorSHA256 != voiceMCPGoodStoreSHA || p.PolicyName != voiceMCPPolicyName ||
		p.EventCreator != "system:serviceaccount:phorvex-system:phorvex-phorvex-console" ||
		p.AuditSourceIdentity == "" || p.MaxRunSeconds != 900 {
		return p, errors.New("reviewed MCP profile invalid")
	}
	return p, nil
}

func loadVoiceMCPProfile(cfg Config) (voiceMCPProfile, error) {
	var p voiceMCPProfile
	if !cfg.VoiceMCPLiveEnabled || !staticSHA256.MatchString(cfg.VoiceMCPLiveProfileSHA256) ||
		cfg.VoiceMCPLiveProfilePath != voiceMCPProfilePath || cfg.AuditSource == nil {
		return p, errors.New("Voice MCP installation disabled or audit unavailable")
	}
	raw, err := readPinnedNamedProfile(cfg.VoiceMCPLiveProfilePath, cfg.VoiceMCPLiveProfileSHA256)
	if err != nil {
		return p, err
	}
	p, err = parseVoiceMCPProfile(raw)
	if err != nil || cfg.AuditSourceIdentity != p.AuditSourceIdentity {
		return p, errors.New("MCP profile or audit identity differs")
	}
	return p, nil
}

type voiceMCPEntry struct {
	GoodDescriptorSHA256 string `json:"goodDescriptorSHA256"`
	OperationID          string `json:"operationId"`
	ToolName             string `json:"toolName"`
}
type voiceMCPRule struct {
	Version       int             `json:"version"`
	DeploymentUID string          `json:"deploymentUID"`
	PolicyUID     string          `json:"policyUID"`
	SourceSHA256  string          `json:"sourceSHA256"`
	Revision      uint64          `json:"revision"`
	OperationID   string          `json:"operationId"`
	Entries       []voiceMCPEntry `json:"entries"`
}

func (r voiceMCPRule) bytes() []byte {
	b, _ := json.Marshal(map[string]any{"version": r.Version, "deploymentUID": r.DeploymentUID,
		"policyUID": r.PolicyUID, "sourceSHA256": r.SourceSHA256, "revision": r.Revision,
		"operationId": r.OperationID, "entries": r.Entries})
	return b
}
func (r voiceMCPRule) sha() string {
	sum := sha256.Sum256(r.bytes())
	return hex.EncodeToString(sum[:])
}
func parseVoiceMCPRule(raw string) (voiceMCPRule, error) {
	var r voiceMCPRule
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal([]byte(raw), &r) != nil || r.Version != 1 ||
		!staticSHA256.MatchString(r.SourceSHA256) || r.DeploymentUID == "" || r.PolicyUID == "" ||
		r.Entries == nil || len(r.Entries) > 2 || r.Revision != uint64(len(r.Entries)) ||
		(r.Revision == 0 && r.OperationID != "") || (r.Revision > 0 && !staticSHA256.MatchString(r.OperationID)) ||
		!bytes.Equal([]byte(raw), r.bytes()) {
		return r, errors.New("MCP rule invalid or noncanonical")
	}
	previous := ""
	for _, entry := range r.Entries {
		good := ""
		if entry.ToolName == "store_directory" {
			good = voiceMCPGoodStoreSHA
		}
		if entry.ToolName == "check_promotions" {
			good = "d5439e3b030abc50693b18b92cf45788ca803fa2d430afcd5a25e3e89b0771e6"
		}
		if entry.ToolName <= previous || entry.GoodDescriptorSHA256 != good || good == "" || !staticSHA256.MatchString(entry.OperationID) {
			return r, errors.New("MCP rule entry invalid")
		}
		previous = entry.ToolName
	}
	return r, nil
}

type voiceMCPSnapshot struct {
	DeploymentUID, PolicyUID, ConfigMapUID, ConfigMapRV, RuleSHA256, SourceSHA256, SourceConfigMapUID string
	MCPDeploymentUID, MCPPodUID, MCPServiceUID, MCPConfigMapUID, MCPSourceSHA256, MCPApprovedImage    string
	MCPPodName, EventCreator                                                                          string
	PolicyGeneration                                                                                  int64
	Rule                                                                                              voiceMCPRule
	Pods                                                                                              []corev1.Pod
	Pins                                                                                              []voiceAgencyPodPin
}

func voiceMCPOwnedBy(cm *corev1.ConfigMap, dep *appsv1.Deployment) bool {
	return cm != nil && dep != nil && len(cm.OwnerReferences) == 1 && cm.OwnerReferences[0].APIVersion == "apps/v1" &&
		cm.OwnerReferences[0].Kind == "Deployment" && cm.OwnerReferences[0].Name == dep.Name &&
		cm.OwnerReferences[0].UID == dep.UID && cm.OwnerReferences[0].Controller != nil && *cm.OwnerReferences[0].Controller
}
func voiceMCPPodPin(p corev1.Pod, source string) (voiceAgencyPodPin, error) {
	pin := voiceAgencyPodPin{Name: p.Name, UID: string(p.UID), SourceSHA256: source}
	for _, status := range p.Status.ContainerStatuses {
		if status.Name == "bot" {
			pin.ContainerID = status.ContainerID
			pin.ImageID = status.ImageID
			pin.RestartCount = status.RestartCount
		}
	}
	if !voiceMCPExactPod(&p, pin) {
		return pin, errors.New("MCP bot Pod incarnation invalid")
	}
	return pin, nil
}

func (s *Server) voiceMCPSnapshot(ctx context.Context, p voiceMCPProfile) (voiceMCPSnapshot, error) {
	var snap voiceMCPSnapshot
	kube, err := clientForContext("")
	if err != nil {
		return snap, err
	}
	dep, err := kube.AppsV1().Deployments("voice").Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.Spec.Replicas == nil || *dep.Spec.Replicas < 1 {
		return snap, errors.New("Voice Deployment unavailable")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if !voiceMCPBotRoute(&corev1.Pod{Spec: dep.Spec.Template.Spec}) || dep.Spec.Template.Annotations["phorvex.ai/voice-mcp-source-sha256"] != p.SourceSHA256 {
		return snap, errors.New("Voice Deployment template MCP source or route differs")
	}
	if err != nil || selector.Empty() {
		return snap, errors.New("Voice selector unavailable")
	}
	pods, err := kube.CoreV1().Pods("voice").List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil || len(pods.Items) != int(*dep.Spec.Replicas) {
		return snap, errors.New("Voice serving roster changed")
	}
	ruleCM, err := kube.CoreV1().ConfigMaps("voice").Get(ctx, voiceMCPRuleCM, metav1.GetOptions{})
	if err != nil || ruleCM.UID == "" || ruleCM.ResourceVersion == "" || !voiceMCPOwnedBy(ruleCM, dep) ||
		len(ruleCM.Data) != 1 || len(ruleCM.BinaryData) != 0 {
		return snap, errors.New("Voice MCP rule ConfigMap unavailable")
	}
	rule, err := parseVoiceMCPRule(ruleCM.Data["rule.json"])
	if err != nil || rule.DeploymentUID != string(dep.UID) || rule.SourceSHA256 != p.SourceSHA256 {
		return snap, errors.New("Voice MCP rule identity differs")
	}
	// The actual named policy remains free to offer other actions. The profile
	// only confirms this action is among its current alternatives.
	var policy struct {
		Metadata struct {
			UID        string `json:"uid"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Mode    string `json:"mode"`
			Actions struct {
				Enabled []string `json:"enabled"`
			} `json:"actions"`
		} `json:"spec"`
	}
	text, err := s.cfg.execText(8e9, "kubectl", "-n", "voice", "get", "phorvexpolicy", p.PolicyName, "-o", "json")
	if err != nil || len(text) > 1<<20 || json.Unmarshal([]byte(text), &policy) != nil || policy.Metadata.UID != rule.PolicyUID ||
		policy.Metadata.Generation < 1 || policy.Spec.Mode != "active" {
		return snap, errors.New("Voice MCP policy unavailable")
	}
	actionEnabled := false
	for _, name := range policy.Spec.Actions.Enabled {
		if name == voiceMCPAction {
			actionEnabled = true
		}
	}
	if !actionEnabled || len(policy.Spec.Actions.Enabled) < 2 {
		return snap, errors.New("Voice MCP action unavailable among normal choices")
	}
	snap = voiceMCPSnapshot{DeploymentUID: string(dep.UID), PolicyUID: rule.PolicyUID, PolicyGeneration: policy.Metadata.Generation,
		ConfigMapUID: string(ruleCM.UID), ConfigMapRV: ruleCM.ResourceVersion, Rule: rule, RuleSHA256: rule.sha(), SourceSHA256: p.SourceSHA256, Pods: pods.Items}
	sort.Slice(snap.Pods, func(i, j int) bool { return snap.Pods[i].Name < snap.Pods[j].Name })
	sourceName := "voice-memory-source-" + p.SourceConfigMapSHA256[:12]
	sourceCM, err := kube.CoreV1().ConfigMaps("voice").Get(ctx, sourceName, metav1.GetOptions{})
	if err != nil || sourceCM.UID == "" || sourceCM.Immutable == nil || !*sourceCM.Immutable || !voiceMCPOwnedBy(sourceCM, dep) ||
		len(sourceCM.BinaryData) != 0 || len(sourceCM.Data) != 4 || sourceCM.Data["bot.py"] == "" ||
		sourceCM.Data["voice_memory_policy.py"] == "" || sourceCM.Data["voice_output_policy.py"] == "" ||
		sourceCM.Data["voice_mcp_policy.py"] == "" {
		return voiceMCPSnapshot{}, errors.New("Voice MCP immutable source unavailable")
	}
	bot, memory, output, mcp := sourceCM.Data["bot.py"], sourceCM.Data["voice_memory_policy.py"], sourceCM.Data["voice_output_policy.py"], sourceCM.Data["voice_mcp_policy.py"]
	if voiceMCPStringSHA(bot+"\x00"+memory+"\x00"+output+"\x00"+mcp) != p.SourceConfigMapSHA256 ||
		voiceMCPStringSHA(bot+"\x00"+memory+"\x00"+mcp) != p.SourceSHA256 {
		return voiceMCPSnapshot{}, errors.New("Voice MCP source bytes differ from both reviewed digests")
	}
	snap.SourceConfigMapUID = string(sourceCM.UID)
	for i := range snap.Pods {
		pod := snap.Pods[i]
		if pod.Annotations["phorvex.ai/voice-mcp-policy-configmap"] != voiceMCPRuleCM ||
			pod.Annotations["phorvex.ai/voice-mcp-source-configmap"] != sourceName ||
			pod.Annotations["phorvex.ai/voice-mcp-event-creator"] != p.EventCreator ||
			pod.Annotations["phorvex.ai/voice-mcp-source-sha256"] != p.SourceSHA256 ||
			!voiceMCPBotRoute(&pod) || !voiceMCPBotMounts(&pod, sourceName, p.MCPSourceSHA256) || len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" ||
			pod.OwnerReferences[0].UID == "" || pod.Status.PodIP == "" {
			return voiceMCPSnapshot{}, errors.New("Voice MCP Pod source or owner differs")
		}
		if _, e := netip.ParseAddr(pod.Status.PodIP); e != nil {
			return voiceMCPSnapshot{}, errors.New("Voice MCP Pod IP invalid")
		}
		rs, e := kube.AppsV1().ReplicaSets("voice").Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
		if e != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].UID != dep.UID {
			return voiceMCPSnapshot{}, errors.New("Voice MCP ReplicaSet owner differs")
		}
		pin, e := voiceMCPPodPin(pod, p.SourceSHA256)
		if e != nil {
			return voiceMCPSnapshot{}, e
		}
		snap.Pins = append(snap.Pins, pin)
		state, e := voiceMCPProbe(ctx, pin, "state", "00000000", "attack", p.SourceSHA256)
		if e != nil || state.StateBody.DeploymentUID != string(dep.UID) || state.StateBody.PolicyUID != rule.PolicyUID ||
			state.StateBody.RuleSHA256 != snap.RuleSHA256 || state.StateBody.Revision != rule.Revision ||
			state.StateBody.OperationID != rule.OperationID || state.StateBody.EntryCount != len(rule.Entries) ||
			state.StateBody.GoodDescriptorSHA256 != voiceMCPGoodStoreSHA {
			return voiceMCPSnapshot{}, errors.New("Voice MCP current Pod rule readback differs")
		}
	}
	// The source of the poisoned descriptor is a separately owned, immutable MCP
	// workload. Require the complete Service routing graph to one exact Ready Pod.
	mcpDep, err := kube.AppsV1().Deployments("mcp").Get(ctx, "mcp-server", metav1.GetOptions{})
	if err != nil || mcpDep.UID == "" {
		return voiceMCPSnapshot{}, errors.New("MCP Deployment unavailable")
	}
	mcpSelector, err := metav1.LabelSelectorAsSelector(mcpDep.Spec.Selector)
	if err != nil || mcpSelector.Empty() {
		return voiceMCPSnapshot{}, errors.New("MCP selector unavailable")
	}
	mcpPods, err := kube.CoreV1().Pods("mcp").List(ctx, metav1.ListOptions{LabelSelector: mcpSelector.String()})
	if err != nil || len(mcpPods.Items) != 1 || mcpPods.Items[0].UID == "" || mcpPods.Items[0].DeletionTimestamp != nil ||
		mcpPods.Items[0].Status.PodIP == "" {
		return voiceMCPSnapshot{}, errors.New("MCP serving Pod roster differs")
	}
	mcpPod := mcpPods.Items[0]
	ready := false
	for _, condition := range mcpPod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || mcpPod.Status.Phase != corev1.PodRunning || mcpDep.Spec.Replicas == nil || *mcpDep.Spec.Replicas != 1 {
		return voiceMCPSnapshot{}, errors.New("MCP Pod not sole Ready replica")
	}
	imageCount, imageStatus := 0, 0
	for _, container := range mcpPod.Spec.Containers {
		if container.Name == "mcp-server" && container.Image == p.MCPImage {
			imageCount++
		}
	}
	for _, status := range mcpPod.Status.ContainerStatuses {
		if status.Name == "mcp-server" && status.Ready &&
			strings.HasSuffix(status.ImageID, p.MCPImage[strings.LastIndex(p.MCPImage, "@")+1:]) {
			imageStatus++
		}
	}
	if imageCount != 1 || imageStatus != 1 {
		return voiceMCPSnapshot{}, errors.New("MCP runtime image differs from reviewed digest")
	}
	templateImage := 0
	for _, container := range mcpDep.Spec.Template.Spec.Containers {
		if container.Name == "mcp-server" && container.Image == p.MCPImage {
			templateImage++
		}
	}
	if templateImage != 1 {
		return voiceMCPSnapshot{}, errors.New("MCP Deployment template image differs")
	}
	if mcpPod.Annotations["phorvex.ai/voice-mcp-source-sha256"] != p.MCPSourceSHA256 ||
		mcpPod.Annotations["phorvex.ai/voice-mcp-source-configmap"] != "voice-mcp-source-"+p.MCPSourceSHA256[:12] ||
		!voiceMCPServerMounts(&mcpPod, "voice-mcp-source-"+p.MCPSourceSHA256[:12]) ||
		len(mcpPod.OwnerReferences) != 1 || mcpPod.OwnerReferences[0].Kind != "ReplicaSet" {
		return voiceMCPSnapshot{}, errors.New("MCP Pod source differs")
	}
	mcpRS, err := kube.AppsV1().ReplicaSets("mcp").Get(ctx, mcpPod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil || mcpRS.UID != mcpPod.OwnerReferences[0].UID || len(mcpRS.OwnerReferences) != 1 || mcpRS.OwnerReferences[0].UID != mcpDep.UID {
		return voiceMCPSnapshot{}, errors.New("MCP owner chain differs")
	}
	mcpCM, err := kube.CoreV1().ConfigMaps("mcp").Get(ctx, "voice-mcp-source-"+p.MCPSourceSHA256[:12], metav1.GetOptions{})
	if err != nil || mcpCM.UID == "" || mcpCM.Immutable == nil || !*mcpCM.Immutable || !voiceMCPOwnedBy(mcpCM, mcpDep) ||
		len(mcpCM.Data) != 1 || len(mcpCM.BinaryData) != 0 || voiceMCPStringSHA(mcpCM.Data["server.py"]) != p.MCPSourceSHA256 {
		return voiceMCPSnapshot{}, errors.New("MCP immutable source differs")
	}
	service, err := kube.CoreV1().Services("mcp").Get(ctx, "mcp-server", metav1.GetOptions{})
	if err != nil || service.UID == "" || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8000 ||
		service.Spec.Ports[0].TargetPort.IntVal != 8000 || service.Spec.Ports[0].Protocol != corev1.ProtocolTCP ||
		len(service.Spec.Selector) == 0 {
		return voiceMCPSnapshot{}, errors.New("MCP Service route differs")
	}
	for key, value := range service.Spec.Selector {
		if mcpPod.Labels[key] != value {
			return voiceMCPSnapshot{}, errors.New("MCP Service selector differs")
		}
	}
	slices, err := kube.DiscoveryV1().EndpointSlices("mcp").List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=mcp-server"})
	if err != nil || len(slices.Items) == 0 {
		return voiceMCPSnapshot{}, errors.New("MCP EndpointSlice unavailable")
	}
	readyCount := 0
	for _, slice := range slices.Items {
		for _, port := range slice.Ports {
			if port.Port == nil || *port.Port != 8000 || port.Protocol == nil || *port.Protocol != corev1.ProtocolTCP {
				return voiceMCPSnapshot{}, errors.New("MCP EndpointSlice port differs")
			}
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {
				continue
			}
			readyCount++
			if endpoint.TargetRef == nil || endpoint.TargetRef.UID != mcpPod.UID || len(endpoint.Addresses) != 1 || endpoint.Addresses[0] != mcpPod.Status.PodIP {
				return voiceMCPSnapshot{}, errors.New("MCP Service has foreign Ready route")
			}
		}
	}
	if readyCount != 1 {
		return voiceMCPSnapshot{}, errors.New("MCP Service Ready route ambiguous")
	}
	snap.MCPDeploymentUID = string(mcpDep.UID)
	snap.MCPPodUID = string(mcpPod.UID)
	snap.MCPPodName = mcpPod.Name
	snap.MCPServiceUID = string(service.UID)
	snap.MCPConfigMapUID = string(mcpCM.UID)
	snap.MCPSourceSHA256 = p.MCPSourceSHA256
	snap.MCPApprovedImage = p.MCPImage
	snap.EventCreator = p.EventCreator
	return snap, nil
}

func voiceMCPSame(a, b voiceMCPSnapshot) bool {
	if a.DeploymentUID != b.DeploymentUID || a.PolicyUID != b.PolicyUID || a.PolicyGeneration != b.PolicyGeneration ||
		a.ConfigMapUID != b.ConfigMapUID || a.RuleSHA256 != b.RuleSHA256 || a.SourceConfigMapUID != b.SourceConfigMapUID ||
		a.MCPDeploymentUID != b.MCPDeploymentUID || a.MCPPodUID != b.MCPPodUID || a.MCPServiceUID != b.MCPServiceUID ||
		a.MCPConfigMapUID != b.MCPConfigMapUID || a.MCPSourceSHA256 != b.MCPSourceSHA256 || a.MCPApprovedImage != b.MCPApprovedImage || len(a.Pins) != len(b.Pins) {
		return false
	}
	for i := range a.Pins {
		if a.Pins[i] != b.Pins[i] {
			return false
		}
	}
	return true
}

func voiceMCPContains(text, token string) bool {
	return strings.Contains(strings.ToUpper(text), strings.ToUpper(token))
}
