package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

func bindVoiceAdmissionObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.VoiceAdmissionObservation = nil
	if reader == nil || p.Namespace != voiceadmissionpolicy.Namespace || !voiceadmissionpolicy.ValidUID(p.UID) || p.VoiceAdmissionConfigMap != voiceadmissionpolicy.ConfigMapName || !voiceadmissionpolicy.ValidSHA(p.VoiceAdmissionSourceSHA256) {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload voiceadmissionpolicy.EventAssertion
	for i := range events {
		e := &events[i]
		if e.Trust != TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorVoiceAdmission || e.CreatorIdentity != voiceadmissionpolicy.Creator || e.Name == "" || !voiceadmissionpolicy.ValidUID(e.UID) || e.TimestampMissing || e.Age < 0 || e.Age >= time.Minute || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		a, err := voiceadmissionpolicy.ParseEvent(e.VoiceAdmissionRaw)
		if err != nil || a.PodUID != p.UID || a.AdmissionSourceSHA256 != p.VoiceAdmissionSourceSHA256 || a.ObservedAtUnixMs > e.CreatedAt.UnixMilli()+1000 || a.ObservedAtUnixMs > e.CreatedAt.Add(e.Age).UnixMilli() || e.CreatedAt.UnixMilli()-a.ObservedAtUnixMs > 60000 || e.CreatedAt.Add(e.Age).UnixMilli()-a.ObservedAtUnixMs >= 60000 {
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
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, live) != nil || string(live.UID) != p.UID || live.DeletionTimestamp != nil || live.Annotations[voiceadmissionpolicy.PolicyConfigMapAnnotation] != p.VoiceAdmissionConfigMap || live.Annotations[voiceadmissionpolicy.SourceSHAAnnotation] != p.VoiceAdmissionSourceSHA256 || live.Annotations[voiceadmissionpolicy.EventCreatorAnnotation] != chosen.CreatorIdentity {
		return
	}
	dep, ok := voiceRefundDeployment(ctx, reader, live)
	if !ok || string(dep.UID) != payload.DeploymentUID {
		return
	}
	source, err := voiceadmissionpolicy.VerifySource(ctx, reader, live, dep)
	if err != nil || source.SourceSHA256 != payload.AdmissionSourceSHA256 || source.LegacyBundleSHA256 != payload.LegacyBundleSHA256 || source.AuthProfileSHA256 != payload.AuthProfileSHA256 {
		return
	}
	cm := &corev1.ConfigMap{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: voiceadmissionpolicy.ConfigMapName}, cm) != nil || !voiceadmissionpolicy.OwnedConfigMap(cm, dep) || string(cm.UID) != payload.PolicyCMUID || cm.ResourceVersion != payload.PolicyResourceVersion || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return
	}
	rule, err := voiceadmissionpolicy.Parse(cm.Data[voiceadmissionpolicy.RuleKey])
	if err != nil || rule.Revision != 0 || rule.SHA256() != payload.RuleSHA256 || rule.DeploymentUID != payload.DeploymentUID || rule.SecurityPolicyUID != payload.SecurityPolicyUID || rule.WrapperCMUID != source.ConfigMapUID || rule.AdmissionSourceSHA256 != payload.AdmissionSourceSHA256 || rule.LegacyBundleSHA256 != payload.LegacyBundleSHA256 || rule.AuthProfileSHA256 != payload.AuthProfileSHA256 {
		return
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: "voice-defense"}, pol) != nil || string(pol.UID) != payload.SecurityPolicyUID || pol.Generation != payload.SecurityPolicyGeneration || pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(live.Labels)) {
		return
	}
	enabled := false
	for _, a := range pol.Spec.Actions.Enabled {
		enabled = enabled || a == v1alpha1.ActionVoiceSessionAdmissionEnforce
	}
	if !enabled {
		return
	}
	p.VoiceAdmissionDeploymentUID = payload.DeploymentUID
	p.VoiceAdmissionObservation = &model.VoiceAdmissionObservation{EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity, ScenarioID: payload.ScenarioID, EvidenceSource: payload.EvidenceSource, TargetPodUID: p.UID, DeploymentUID: payload.DeploymentUID, ConfigMapUID: payload.PolicyCMUID, ConfigMapResourceVersion: payload.PolicyResourceVersion, RuleSHA256: payload.RuleSHA256, SourceSHA256: payload.AdmissionSourceSHA256, SessionID: payload.SessionID, PolicyName: pol.Name, PolicyUID: payload.SecurityPolicyUID, PolicyGeneration: payload.SecurityPolicyGeneration, SelectedRevision: 0, Assertion: payload, ObservedAt: time.UnixMilli(payload.ObservedAtUnixMs)}
}
