package console

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	voiceAdmissionScenario    = "voice-unauthenticated-media-admission"
	voiceAdmissionAction      = "voice-session-admission-enforce"
	voiceAdmissionRoute       = "/api/voice/admission/live/fire"
	voiceAdmissionProfilePath = "/etc/phorvex-voice-admission/profile.json"
)

type voiceAdmissionProfile struct {
	Version               int    `json:"version"`
	DeploymentUID         string `json:"deploymentUID"`
	PolicyCMUID           string `json:"policyCMUID"`
	AdmissionSourceSHA256 string `json:"admissionSourceSHA256"`
	LegacyBundleSHA256    string `json:"legacyBundleSHA256"`
	AuthProfileSHA256     string `json:"authProfileSHA256"`
	WrapperConfigMapName  string `json:"wrapperConfigMapName"`
	LegacyConfigMapName   string `json:"legacyConfigMapName"`
	ProbeSHA256           string `json:"probeSHA256"`
	AudioSHA256           string `json:"audioSHA256"`
	EventCreator          string `json:"eventCreator"`
	AuditSourceIdentity   string `json:"auditSourceIdentity"`
	MaxRunSeconds         int    `json:"maxRunSeconds"`
}

func parseVoiceAdmissionProfile(raw []byte) (voiceAdmissionProfile, error) {
	var p voiceAdmissionProfile
	if voiceadmissionpolicy.ExactDecode(raw, &p) != nil || p.Version != 1 || !voiceadmissionpolicy.ValidUID(p.DeploymentUID) || !voiceadmissionpolicy.ValidUID(p.PolicyCMUID) ||
		!voiceadmissionpolicy.ValidSHA(p.AdmissionSourceSHA256) || !voiceadmissionpolicy.ValidSHA(p.LegacyBundleSHA256) || !voiceadmissionpolicy.ValidSHA(p.AuthProfileSHA256) ||
		!validObjectName(p.WrapperConfigMapName) || p.LegacyConfigMapName != "voice-memory-source-"+p.LegacyBundleSHA256[:12] || p.ProbeSHA256 != voiceAdmissionProbeSHA() ||
		p.AudioSHA256 != voiceAdmissionAudioSHA || p.EventCreator != eventtrust.Injector() || p.AuditSourceIdentity == "" || p.MaxRunSeconds != 900 ||
		string(raw) != string(voiceAdmissionCanonical(p)) {
		return p, errors.New("reviewed admission profile invalid")
	}
	return p, nil
}
func validObjectName(name string) bool {
	return len(name) > 0 && len(name) <= 63 && regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(name)
}
func loadVoiceAdmissionProfile(cfg Config) (voiceAdmissionProfile, error) {
	if !cfg.VoiceAdmissionLiveEnabled || cfg.VoiceAdmissionLiveProfilePath != voiceAdmissionProfilePath || !staticSHA256.MatchString(cfg.VoiceAdmissionLiveProfileSHA256) || cfg.AuditSource == nil {
		return voiceAdmissionProfile{}, errors.New("reviewed admission installation disabled")
	}
	raw, e := readPinnedNamedProfile(cfg.VoiceAdmissionLiveProfilePath, cfg.VoiceAdmissionLiveProfileSHA256)
	if e != nil {
		return voiceAdmissionProfile{}, e
	}
	p, e := parseVoiceAdmissionProfile(raw)
	if e != nil || p.AuditSourceIdentity != cfg.AuditSourceIdentity {
		return p, errors.New("admission audit identity differs")
	}
	return p, nil
}

type voiceAdmissionSnapshot struct {
	DeploymentUID, PolicyUID, ConfigMapUID, ConfigMapRV, RuleSHA256, WrapperCMUID, LegacyCMUID, EventCreator string
	PolicyGeneration                                                                                         int64
	Rule                                                                                                     voiceadmissionpolicy.Rule
	Pods                                                                                                     []corev1.Pod
	Pins                                                                                                     []voiceAgencyPodPin
	States                                                                                                   []voiceadmissionpolicy.State
}

func voiceAdmissionStateMatches(state voiceadmissionpolicy.State, snap voiceAdmissionSnapshot, podUID string) bool {
	age := time.Since(time.UnixMilli(state.ObservedAtUnixMs))
	return state.Version == 1 && state.PodUID == podUID && state.DeploymentUID == snap.DeploymentUID && state.PolicyCMUID == snap.ConfigMapUID && state.PolicyResourceVersion == snap.ConfigMapRV &&
		state.RuleSHA256 == snap.RuleSHA256 && state.Revision == snap.Rule.Revision && state.Mode == snap.Rule.Mode && state.OperationID == snap.Rule.OperationID &&
		state.AdmissionSourceSHA256 == snap.Rule.AdmissionSourceSHA256 && state.LegacyBundleSHA256 == snap.Rule.LegacyBundleSHA256 && state.AuthProfileSHA256 == snap.Rule.AuthProfileSHA256 && age >= 0 && age < 15*time.Second
}
func (s *Server) voiceAdmissionSnapshot(ctx context.Context, p voiceAdmissionProfile) (voiceAdmissionSnapshot, error) {
	var snap voiceAdmissionSnapshot
	kube, e := clientForContext("")
	if e != nil {
		return snap, e
	}
	config, e := restConfigFor("")
	if e != nil {
		return snap, e
	}
	reader, e := client.New(config, client.Options{Scheme: scheme.Scheme})
	if e != nil {
		return snap, e
	}
	dep, e := kube.AppsV1().Deployments("voice").Get(ctx, "voice-bot", metav1.GetOptions{})
	if e != nil || string(dep.UID) != p.DeploymentUID || dep.Spec.Replicas == nil || *dep.Spec.Replicas < 1 || *dep.Spec.Replicas > 8 {
		return snap, errors.New("admission Deployment differs")
	}
	selector, e := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if e != nil || selector.Empty() {
		return snap, errors.New("admission selector missing")
	}
	pods, e := kube.CoreV1().Pods("voice").List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if e != nil || len(pods.Items) != int(*dep.Spec.Replicas) {
		return snap, errors.New("admission serving set unresolved")
	}
	cm, e := kube.CoreV1().ConfigMaps("voice").Get(ctx, voiceadmissionpolicy.ConfigMapName, metav1.GetOptions{})
	if e != nil || !voiceadmissionpolicy.OwnedConfigMap(cm, dep) || string(cm.UID) != p.PolicyCMUID || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return snap, errors.New("admission policy owner or UID differs")
	}
	rule, e := voiceadmissionpolicy.Parse(cm.Data[voiceadmissionpolicy.RuleKey])
	if e != nil || rule.DeploymentUID != p.DeploymentUID || rule.AdmissionSourceSHA256 != p.AdmissionSourceSHA256 || rule.LegacyBundleSHA256 != p.LegacyBundleSHA256 || rule.AuthProfileSHA256 != p.AuthProfileSHA256 {
		return snap, errors.New("admission policy source differs")
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
	raw, e := s.cfg.execText(8*time.Second, "kubectl", "-n", "voice", "get", "phorvexpolicy", "voice-defense", "-o", "json")
	if e != nil || len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &policy) != nil || policy.Metadata.UID != rule.SecurityPolicyUID || policy.Metadata.Generation <= 0 || policy.Spec.Mode != "active" || len(policy.Spec.Actions.Enabled) < 2 {
		return snap, errors.New("admission governance unavailable")
	}
	found := false
	for _, a := range policy.Spec.Actions.Enabled {
		found = found || a == voiceAdmissionAction
	}
	if !found {
		return snap, errors.New("admission action absent from normal alternatives")
	}
	snap = voiceAdmissionSnapshot{DeploymentUID: p.DeploymentUID, PolicyUID: policy.Metadata.UID, PolicyGeneration: policy.Metadata.Generation, ConfigMapUID: string(cm.UID), ConfigMapRV: cm.ResourceVersion,
		Rule: rule, RuleSHA256: rule.SHA256(), WrapperCMUID: rule.WrapperCMUID, EventCreator: p.EventCreator, Pods: pods.Items}
	sort.Slice(snap.Pods, func(i, j int) bool { return snap.Pods[i].Name < snap.Pods[j].Name })
	for _, pod := range snap.Pods {
		if len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" || pod.OwnerReferences[0].UID == "" || pod.Annotations[voiceadmissionpolicy.EventCreatorAnnotation] != p.EventCreator {
			return voiceAdmissionSnapshot{}, errors.New("admission Pod owner/creator differs")
		}
		rs, e := kube.AppsV1().ReplicaSets("voice").Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
		if e != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].UID != dep.UID {
			return voiceAdmissionSnapshot{}, errors.New("admission ReplicaSet ownership differs")
		}
		source, e := voiceadmissionpolicy.VerifySource(ctx, reader, &pod, dep)
		if e != nil || source.ConfigMapName != p.WrapperConfigMapName || source.ConfigMapUID != rule.WrapperCMUID || source.SourceSHA256 != p.AdmissionSourceSHA256 || source.LegacyBundleSHA256 != p.LegacyBundleSHA256 || source.AuthProfileSHA256 != p.AuthProfileSHA256 {
			return voiceAdmissionSnapshot{}, errors.New("admission source attestation differs")
		}
		if snap.LegacyCMUID != "" && snap.LegacyCMUID != source.LegacyConfigMapUID {
			return voiceAdmissionSnapshot{}, errors.New("admission legacy bundle UID drift")
		}
		snap.LegacyCMUID = source.LegacyConfigMapUID
		pin := voiceAgencyPodPin{Name: pod.Name, UID: string(pod.UID), SourceSHA256: p.AdmissionSourceSHA256, SourceAnnotation: voiceadmissionpolicy.SourceSHAAnnotation}
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == "bot" {
				pin.ContainerID = status.ContainerID
				pin.ImageID = status.ImageID
				pin.RestartCount = status.RestartCount
			}
		}
		if !voiceAgencyExactPod(&pod, pin) {
			return voiceAdmissionSnapshot{}, errors.New("admission serving incarnation differs")
		}
		state, e := voiceAdmissionProbe(ctx, pin, "state", "00000000", "", "")
		if e != nil || state.Status != 200 || !voiceAdmissionStateMatches(state.State, snap, pin.UID) {
			return voiceAdmissionSnapshot{}, errors.New("admission authenticated state differs")
		}
		snap.Pins = append(snap.Pins, pin)
		snap.States = append(snap.States, state.State)
	}
	service, e := kube.CoreV1().Services("voice").Get(ctx, "voice-bot", metav1.GetOptions{})
	if e != nil || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8080 || service.Spec.Ports[0].TargetPort.IntVal != 8080 || len(service.Spec.Selector) == 0 {
		return voiceAdmissionSnapshot{}, errors.New("admission Service route differs")
	}
	slices, e := kube.DiscoveryV1().EndpointSlices("voice").List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=voice-bot"})
	if e != nil {
		return voiceAdmissionSnapshot{}, e
	}
	seen := map[string]bool{}
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {
				continue
			}
			if endpoint.TargetRef == nil || seen[string(endpoint.TargetRef.UID)] {
				return voiceAdmissionSnapshot{}, errors.New("admission serving endpoint ambiguous")
			}
			match := false
			for _, pod := range snap.Pods {
				if pod.UID == endpoint.TargetRef.UID && len(endpoint.Addresses) == 1 && endpoint.Addresses[0] == pod.Status.PodIP {
					match = true
					for key, value := range service.Spec.Selector {
						if pod.Labels[key] != value {
							match = false
						}
					}
				}
			}
			if !match {
				return voiceAdmissionSnapshot{}, errors.New("admission foreign serving endpoint")
			}
			seen[string(endpoint.TargetRef.UID)] = true
		}
	}
	if len(seen) != len(snap.Pods) {
		return voiceAdmissionSnapshot{}, errors.New("admission serving endpoint set incomplete")
	}
	return snap, nil
}
func voiceAdmissionSame(a, b voiceAdmissionSnapshot, rule bool) bool {
	if a.DeploymentUID != b.DeploymentUID || a.PolicyUID != b.PolicyUID || a.PolicyGeneration != b.PolicyGeneration || a.ConfigMapUID != b.ConfigMapUID || a.WrapperCMUID != b.WrapperCMUID || a.LegacyCMUID != b.LegacyCMUID || len(a.Pins) != len(b.Pins) {
		return false
	}
	for i := range a.Pins {
		if a.Pins[i] != b.Pins[i] {
			return false
		}
	}
	return !rule || a.RuleSHA256 == b.RuleSHA256 && a.ConfigMapRV == b.ConfigMapRV
}
