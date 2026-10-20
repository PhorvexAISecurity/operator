package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
)

const litellmClientHorizon = 60 * time.Second
const litellmConsoleCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"

// bindLiteLLMClientObservation grants a fact only for one fresh trusted event
// whose typed identities match the current gateway, Service, policy, and both
// Ready serving Pod lifetimes. Any competing assertion suppresses the fact.
func bindLiteLLMClientObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.LiteLLMClientObservation = nil
	if p.Namespace != litellmclient.Namespace || p.UID == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload litellmclient.Observation
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorLiteLLMClientAbuse ||
			e.CreatorIdentity != litellmConsoleCreator || e.Name == "" || e.UID == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= litellmClientHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		candidate, parseErr := litellmclient.ParseObservation(e.LiteLLMClientRaw)
		if parseErr != nil || candidate.TargetPodUID != p.UID || candidate.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			e.CreatedAt.Sub(candidate.ObservedAt) > litellmClientHorizon ||
			e.CreatedAt.Add(e.Age).Sub(candidate.ObservedAt) >= litellmClientHorizon {
			continue
		}
		if chosen != nil {
			return
		}
		chosen, payload = e, candidate
	}
	if chosen == nil {
		return
	}
	live, e := litellmclient.ValidateLive(ctx, reader, payload.TargetPodUID, payload.PeerPodUID)
	_, alreadyDenied := live.State.Entry(payload.ClientSHA256)
	if e != nil || alreadyDenied || len(live.State.Entries) >= 256 ||
		live.PolicyUID != payload.ConfigMapUID || live.ClientsUID != payload.ClientsConfigMapUID ||
		live.ServiceUID != payload.ServiceUID || live.SeedSHA256 != payload.SeedSHA256 {
		return
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: payload.PolicyName}, policy); e != nil ||
		string(policy.UID) != payload.PolicyUID || policy.Generation != payload.PolicyGeneration {
		return
	}
	selector, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || selector.Empty() {
		return
	}
	pod := &corev1.Pod{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, pod); e != nil || string(pod.UID) != p.UID ||
		!selector.Matches(labels.Set(pod.Labels)) {
		return
	}
	p.LiteLLMClientObservation = &model.LiteLLMClientObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		TargetPodUID: payload.TargetPodUID, PeerPodUID: payload.PeerPodUID,
		ClientSHA256: payload.ClientSHA256, ConfigMapUID: payload.ConfigMapUID,
		ClientsConfigMapUID: payload.ClientsConfigMapUID, SeedSHA256: payload.SeedSHA256,
		ServiceUID: payload.ServiceUID, GatewaySourceSHA256: live.SourceSHA256,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		ObservedAt: payload.ObservedAt,
	}
}
