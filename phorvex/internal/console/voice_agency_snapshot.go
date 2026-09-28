package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/voicerefundpolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const voiceAgencyConfigMapName = voicerefundpolicy.ConfigMapName
const voiceAgencyAction = "voice-refund-pair-deny"

type voiceAgencyRule = voicerefundpolicy.Rule
type voiceAgencySnapshot struct {
	DeploymentUID, PolicyUID, ConfigMapUID, ConfigMapRV, RuleSHA256, SourceSHA256, EventCreator string
	PolicyGeneration                                                                            int64
	Rule                                                                                        voiceAgencyRule
	Pods                                                                                        []corev1.Pod
	Pins                                                                                        []voiceAgencyPodPin
}

func parseVoiceAgencyRule(raw string) (voiceAgencyRule, string, error) {
	rule, err := voicerefundpolicy.Parse(raw)
	if err != nil {
		return rule, "", err
	}
	return rule, rule.SHA256(), nil
}

func voiceAgencyRequiredMode(p *corev1.Pod) bool {
	for _, container := range p.Spec.Containers {
		if container.Name != "bot" {
			continue
		}
		policyCount, testCount := 0, 0
		for _, env := range container.Env {
			if env.Name == "VOICE_REFUND_POLICY_REQUIRED" {
				if env.Value != "true" || env.ValueFrom != nil {
					return false
				}
				policyCount++
			}
			if env.Name == "VOICE_AGENCY_TEST_ENABLED" {
				if env.Value != "true" || env.ValueFrom != nil {
					return false
				}
				testCount++
			}
		}
		return policyCount == 1 && testCount == 1
	}
	return false
}

func voiceAgencyServingPod(p *corev1.Pod, dep *appsv1.Deployment, source string) bool {
	if p == nil || dep == nil || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.UID == "" ||
		p.Annotations["phorvex.ai/voice-refund-source-sha256"] != source ||
		p.Annotations["phorvex.ai/voice-refund-policy-configmap"] != voiceAgencyConfigMapName ||
		len(p.OwnerReferences) != 1 || p.OwnerReferences[0].APIVersion != "apps/v1" ||
		p.OwnerReferences[0].Kind != "ReplicaSet" || p.OwnerReferences[0].UID == "" || !voiceAgencyRequiredMode(p) ||
		!voiceAgencyActuatorMounts(p) || p.Status.PodIP == "" {
		return false
	}
	if _, err := netip.ParseAddr(p.Status.PodIP); err != nil {
		return false
	}
	ready := false
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	return ready
}

func voiceAgencyActuatorMounts(p *corev1.Pod) bool {
	var bot *corev1.Container
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == "bot" {
			bot = &p.Spec.Containers[i]
		}
	}
	if bot == nil {
		return false
	}
	paths := map[string]string{}
	state := ""
	for _, mount := range bot.VolumeMounts {
		if mount.SubPath != "" {
			continue
		}
		if mount.ReadOnly {
			paths[mount.MountPath] = mount.Name
		}
		if mount.MountPath == "/var/lib/phorvex-voice-memory" {
			state = mount.Name
		}
	}
	policy, secret := paths["/etc/phorvex/voice-refund-policy"], paths["/etc/phorvex/voice-memory-state-token"]
	if policy == "" || secret == "" || state == "" {
		return false
	}
	valid := 0
	for _, volume := range p.Spec.Volumes {
		if volume.Name == policy && volume.ConfigMap != nil && volume.ConfigMap.Name == voiceAgencyConfigMapName &&
			(volume.ConfigMap.Optional == nil || !*volume.ConfigMap.Optional) {
			valid++
		}
		if volume.Name == secret && volume.Secret != nil && volume.Secret.SecretName == "voice-memory-state-token" {
			valid++
		}
		if volume.Name == state && volume.EmptyDir != nil {
			valid++
		}
	}
	return valid == 3
}

func voiceAgencyPin(p corev1.Pod, source string) (voiceAgencyPodPin, error) {
	pin := voiceAgencyPodPin{Name: p.Name, UID: string(p.UID), SourceSHA256: source}
	for _, status := range p.Status.ContainerStatuses {
		if status.Name == "bot" {
			pin.ContainerID = status.ContainerID
			pin.ImageID = status.ImageID
			pin.RestartCount = status.RestartCount
		}
	}
	if !voiceAgencyExactPod(&p, pin) {
		return pin, errors.New("Voice serving Pod/container/source not exact")
	}
	return pin, nil
}

func (s *Server) voiceAgencySnapshot(ctx context.Context, p voiceAgencyProfile) (voiceAgencySnapshot, error) {
	var snap voiceAgencySnapshot
	kube, e := clientForContext("")
	if e != nil {
		return snap, e
	}
	dep, e := kube.AppsV1().Deployments("voice").Get(ctx, "voice-bot", metav1.GetOptions{})
	if e != nil || dep.UID == "" || dep.Spec.Replicas == nil {
		return snap, errors.New("Voice Deployment unavailable")
	}
	selector, e := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if e != nil || selector.Empty() {
		return snap, errors.New("Voice Deployment selector unavailable")
	}
	pods, e := kube.CoreV1().Pods("voice").List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if e != nil || len(pods.Items) == 0 || len(pods.Items) != int(*dep.Spec.Replicas) {
		return snap, errors.New("Voice serving Pod roster changed")
	}
	cm, e := kube.CoreV1().ConfigMaps("voice").Get(ctx, voiceAgencyConfigMapName, metav1.GetOptions{})
	if e != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 1 ||
		cm.OwnerReferences[0].APIVersion != "apps/v1" || cm.OwnerReferences[0].Kind != "Deployment" ||
		cm.OwnerReferences[0].Name != dep.Name || cm.OwnerReferences[0].UID != dep.UID ||
		cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return snap, errors.New("Voice refund ConfigMap owner or shape differs")
	}
	rule, ruleSHA, e := parseVoiceAgencyRule(cm.Data["rule.json"])
	if e != nil || rule.DeploymentUID != string(dep.UID) || rule.SourceSHA256 != p.SourceSHA256 {
		return snap, errors.New("Voice refund rule source or owner differs")
	}
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
	raw, e := s.cfg.execText(8*time.Second, "kubectl", "-n", "voice", "get", "phorvexpolicy", p.PolicyName, "-o", "json")
	if e != nil || len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &policy) != nil || policy.Metadata.UID == "" ||
		policy.Metadata.Generation < 1 || policy.Metadata.UID != rule.PolicyUID || policy.Spec.Mode != "active" {
		return snap, errors.New("Voice PhorvexPolicy identity unavailable")
	}
	enabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if action == voiceAgencyAction {
			enabled = true
		}
	}
	if !enabled {
		return snap, errors.New("Voice refund action unavailable among policy choices")
	}
	snap = voiceAgencySnapshot{DeploymentUID: string(dep.UID), PolicyUID: policy.Metadata.UID, PolicyGeneration: policy.Metadata.Generation,
		ConfigMapUID: string(cm.UID), ConfigMapRV: cm.ResourceVersion, Rule: rule, RuleSHA256: ruleSHA, SourceSHA256: p.SourceSHA256, Pods: pods.Items}
	sort.Slice(snap.Pods, func(i, j int) bool { return snap.Pods[i].Name < snap.Pods[j].Name })
	for i := range snap.Pods {
		pod := &snap.Pods[i]
		if err := voiceConsoleWrapperSource(ctx, pod, dep); err != nil {
			return voiceAgencySnapshot{}, err
		}
		if !voiceAgencyServingPod(pod, dep, p.SourceSHA256) ||
			pod.Annotations["phorvex.ai/voice-refund-policy-configmap"] != voiceAgencyConfigMapName {
			return voiceAgencySnapshot{}, errors.New("Voice serving Pod mode or rule mount differs")
		}
		rs, e := kube.AppsV1().ReplicaSets("voice").Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
		if e != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].Kind != "Deployment" || rs.OwnerReferences[0].UID != dep.UID {
			return voiceAgencySnapshot{}, errors.New("Voice ReplicaSet owner differs")
		}
		creator := pod.Annotations["phorvex.ai/voice-refund-event-creator"]
		if creator == "" || (snap.EventCreator != "" && creator != snap.EventCreator) {
			return voiceAgencySnapshot{}, errors.New("Voice event creator differs")
		}
		snap.EventCreator = creator
		pin, e := voiceAgencyPin(*pod, p.SourceSHA256)
		if e != nil {
			return voiceAgencySnapshot{}, e
		}
		snap.Pins = append(snap.Pins, pin)
		state, e := voiceAgencyProbe(ctx, pin, "state", "00000000", "", nil, "")
		if e != nil || state.Status != 200 || !state.Body.Ready || state.Body.PodUID != string(pod.UID) ||
			state.Body.DeploymentUID != snap.DeploymentUID || state.Body.PolicyUID != snap.PolicyUID ||
			state.Body.SourceSHA256 != snap.SourceSHA256 || state.Body.RuleSHA256 != snap.RuleSHA256 ||
			state.Body.Revision != rule.Revision || state.Body.OperationID != rule.OperationID || state.Body.EntryCount != len(rule.Entries) {
			return voiceAgencySnapshot{}, errors.New("Voice all-Pod authenticated refund state differs")
		}
	}
	if snap.EventCreator != p.EventCreator {
		return voiceAgencySnapshot{}, errors.New("Voice event creator not reviewed console SA")
	}
	return snap, nil
}

func voiceAgencySnapshotHasPod(s voiceAgencySnapshot, name, uid string) bool {
	for _, p := range s.Pods {
		if p.Name == name && string(p.UID) == uid {
			return true
		}
	}
	return false
}
func voiceAgencyOwnedBy(p *corev1.Pod, dep *appsv1.Deployment) bool {
	return voiceAgencyServingPod(p, dep, p.Annotations["phorvex.ai/voice-refund-source-sha256"])
}
