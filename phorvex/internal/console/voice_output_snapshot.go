package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const voiceOutputAction = "voice-output-policy-activate"

type voiceOutputSnapshot struct {
	DeploymentUID, PolicyUID, ConfigMapUID, ConfigMapRV, RuleSHA256, SourceSHA256, EventCreator string
	PolicyGeneration                                                                            int64
	Rule                                                                                        voiceoutputpolicy.Rule
	Pods                                                                                        []corev1.Pod
	Pins                                                                                        []voiceAgencyPodPin
}

func voiceOutputRequiredMode(p *corev1.Pod) bool {
	if p == nil {
		return false
	}
	for _, container := range p.Spec.Containers {
		if container.Name != "bot" {
			continue
		}
		policy, test := 0, 0
		for _, env := range container.Env {
			switch env.Name {
			case "VOICE_OUTPUT_POLICY_REQUIRED":
				if env.Value == "true" && env.ValueFrom == nil {
					policy++
				}
			case "VOICE_OUTPUT_TEST_ENABLED":
				if env.Value == "true" && env.ValueFrom == nil {
					test++
				}
			}
		}
		return policy == 1 && test == 1
	}
	return false
}

func voiceOutputMounts(p *corev1.Pod) bool {
	var bot *corev1.Container
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == "bot" {
			bot = &p.Spec.Containers[i]
		}
	}
	if bot == nil {
		return false
	}
	paths, state := map[string]string{}, ""
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
	policy, token := paths["/etc/phorvex/voice-output-policy"], paths["/etc/phorvex/voice-memory-state-token"]
	if policy == "" || token == "" || state == "" {
		return false
	}
	found := 0
	for _, volume := range p.Spec.Volumes {
		if volume.Name == policy && volume.ConfigMap != nil && volume.ConfigMap.Name == voiceoutputpolicy.ConfigMapName &&
			(volume.ConfigMap.Optional == nil || !*volume.ConfigMap.Optional) {
			found++
		}
		if volume.Name == token && volume.Secret != nil && volume.Secret.SecretName == "voice-memory-state-token" {
			found++
		}
		if volume.Name == state && volume.EmptyDir != nil {
			found++
		}
	}
	return found == 3
}

func voiceOutputServingPod(p *corev1.Pod, source string) bool {
	if p == nil || p.Namespace != "voice" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
		p.UID == "" || p.Status.PodIP == "" || p.Annotations[voiceOutputSourceAnnotation] != source ||
		p.Annotations["phorvex.ai/voice-output-policy-configmap"] != voiceoutputpolicy.ConfigMapName ||
		len(p.OwnerReferences) != 1 || p.OwnerReferences[0].APIVersion != "apps/v1" ||
		p.OwnerReferences[0].Kind != "ReplicaSet" || p.OwnerReferences[0].UID == "" ||
		!voiceOutputRequiredMode(p) || !voiceOutputMounts(p) {
		return false
	}
	if _, err := netip.ParseAddr(p.Status.PodIP); err != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func voiceOutputPin(p corev1.Pod, source string) (voiceAgencyPodPin, error) {
	pin := voiceAgencyPodPin{Name: p.Name, UID: string(p.UID), SourceSHA256: source, SourceAnnotation: voiceOutputSourceAnnotation}
	for _, item := range p.Status.ContainerStatuses {
		if item.Name == "bot" {
			pin.ContainerID, pin.ImageID, pin.RestartCount = item.ContainerID, item.ImageID, item.RestartCount
		}
	}
	if !voiceAgencyExactPod(&p, pin) {
		return pin, errors.New("Voice output Pod/container/source differs")
	}
	return pin, nil
}

func voiceOutputStateMatches(reply voiceOutputProbeReply, snap voiceOutputSnapshot, podUID, markerSHA string) bool {
	b := reply.Body
	if reply.Operation != "state" || reply.Status != 200 || !b.Ready || b.Version != 1 || b.PodUID != podUID ||
		b.ConfigMapUID != snap.ConfigMapUID || b.DeploymentUID != snap.DeploymentUID ||
		b.PolicyUID != snap.PolicyUID || b.SourceSHA256 != snap.SourceSHA256 || b.RuleSHA256 != snap.RuleSHA256 ||
		b.Revision != snap.Rule.Revision || b.OperationID != snap.Rule.OperationID ||
		b.EntryCount != len(snap.Rule.Entries) || b.MarkerSHA256 != markerSHA {
		return false
	}
	wantOp := ""
	for _, entry := range snap.Rule.Entries {
		if entry.MarkerSHA256 == markerSHA {
			wantOp = entry.OperationID
		}
	}
	return b.Active == (wantOp != "") && b.MatchedOperationID == wantOp
}

func (s *Server) voiceOutputSnapshot(ctx context.Context, p voiceOutputProfile, markerSHA string) (voiceOutputSnapshot, error) {
	var snap voiceOutputSnapshot
	kube, err := clientForContext("")
	if err != nil {
		return snap, err
	}
	dep, err := kube.AppsV1().Deployments("voice").Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.Spec.Replicas == nil {
		return snap, errors.New("Voice Deployment unavailable")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return snap, errors.New("Voice selector unavailable")
	}
	pods, err := kube.CoreV1().Pods("voice").List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil || len(pods.Items) == 0 || len(pods.Items) != int(*dep.Spec.Replicas) {
		return snap, errors.New("Voice serving roster differs")
	}
	cm, err := kube.CoreV1().ConfigMaps("voice").Get(ctx, voiceoutputpolicy.ConfigMapName, metav1.GetOptions{})
	if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
		len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].APIVersion != "apps/v1" ||
		cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].Name != dep.Name ||
		cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Controller == nil ||
		!*cm.OwnerReferences[0].Controller || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return snap, errors.New("Voice output ConfigMap owner or shape differs")
	}
	rule, err := voiceoutputpolicy.Parse(cm.Data[voiceoutputpolicy.RuleKey])
	if err != nil || rule.ConfigMapUID != string(cm.UID) || rule.DeploymentUID != string(dep.UID) || rule.SourceSHA256 != p.SourceSHA256 {
		return snap, errors.New("Voice output rule identity differs")
	}
	protected, err := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, voiceOutputJournalName, metav1.GetOptions{})
	if err != nil {
		return snap, errors.New("Voice output protected journal unavailable")
	}
	history, err := voiceOutputJournalRead(protected)
	if err != nil || len(history.Receipts) != int(rule.Revision) {
		return snap, errors.New("Voice output protected history differs from rule")
	}
	if len(history.Receipts) > 0 {
		for _, receipt := range history.Receipts {
			if receipt.Phase != "terminal-full" {
				return snap, errors.New("Voice output protected operation pending")
			}
		}
		last := history.Receipts[len(history.Receipts)-1]
		if last.DesiredRuleSHA256 != rule.SHA256() || last.ConfigMapUID != string(cm.UID) ||
			last.DeploymentUID != string(dep.UID) || last.PolicyUID != rule.PolicyUID || last.SourceSHA256 != p.SourceSHA256 {
			return snap, errors.New("Voice output protected rule lineage differs")
		}
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
	raw, err := s.cfg.execText(8*time.Second, "kubectl", "-n", "voice", "get", "phorvexpolicy", p.PolicyName, "-o", "json")
	if err != nil || len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &policy) != nil || policy.Metadata.UID == "" ||
		policy.Metadata.Generation < 1 || policy.Metadata.UID != rule.PolicyUID || policy.Spec.Mode != "active" {
		return snap, errors.New("Voice PhorvexPolicy unavailable")
	}
	actionEnabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if action == voiceOutputAction {
			actionEnabled = true
		}
	}
	if !actionEnabled {
		return snap, errors.New("Voice output action not available among policy choices")
	}
	snap = voiceOutputSnapshot{DeploymentUID: string(dep.UID), PolicyUID: policy.Metadata.UID,
		PolicyGeneration: policy.Metadata.Generation, ConfigMapUID: string(cm.UID), ConfigMapRV: cm.ResourceVersion,
		Rule: rule, RuleSHA256: rule.SHA256(), SourceSHA256: p.SourceSHA256, Pods: pods.Items}
	sort.Slice(snap.Pods, func(i, j int) bool { return snap.Pods[i].Name < snap.Pods[j].Name })
	for i := range snap.Pods {
		pod := &snap.Pods[i]
		if !voiceOutputServingPod(pod, p.SourceSHA256) {
			return voiceOutputSnapshot{}, errors.New("Voice output serving Pod differs")
		}
		rs, getErr := kube.AppsV1().ReplicaSets("voice").Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
		if getErr != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 ||
			rs.OwnerReferences[0].Kind != "Deployment" || rs.OwnerReferences[0].UID != dep.UID {
			return voiceOutputSnapshot{}, errors.New("Voice output ReplicaSet owner differs")
		}
		creator := pod.Annotations["phorvex.ai/voice-output-event-creator"]
		if creator == "" || (snap.EventCreator != "" && snap.EventCreator != creator) {
			return voiceOutputSnapshot{}, errors.New("Voice output creator differs")
		}
		snap.EventCreator = creator
		pin, getErr := voiceOutputPin(*pod, p.SourceSHA256)
		if getErr != nil {
			return voiceOutputSnapshot{}, getErr
		}
		snap.Pins = append(snap.Pins, pin)
		readback, readErr := voiceOutputProbe(ctx, pin, "state", "00000000", "", "", markerSHA)
		if readErr != nil || !voiceOutputStateMatches(readback, snap, pin.UID, markerSHA) {
			return voiceOutputSnapshot{}, errors.New("Voice output authenticated state differs")
		}
	}
	if snap.EventCreator != p.EventCreator {
		return voiceOutputSnapshot{}, errors.New("Voice output creator not reviewed")
	}
	return snap, nil
}

func voiceOutputSnapshotHasPod(snap voiceOutputSnapshot, name, uid string) bool {
	for _, pod := range snap.Pods {
		if pod.Name == name && string(pod.UID) == uid {
			return true
		}
	}
	return false
}
