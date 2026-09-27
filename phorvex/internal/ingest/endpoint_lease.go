package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/model"
)

const endpointLeaseHorizon = 60 * time.Second
const endpointLeaseConsoleCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"

// bindEndpointLeaseObservation accepts a synthetic assertion only after current
// Kubernetes source, policy, Secret metadata, Service, and Pod authority agree.
// Authenticated proxy status is a separate native SupportsAction check before
// selection; an event alone can never establish that capability.
func bindEndpointLeaseObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	bindEndpointLeaseObservationWithValidator(ctx, reader, p, events, endpointlease.ValidateLive)
}

type endpointLeaseLiveValidator func(context.Context, client.Reader, string, string, string) (endpointlease.Live, error)

func bindEndpointLeaseObservationWithValidator(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo, validate endpointLeaseLiveValidator) {
	p.EndpointLeaseObservation = nil
	approved, image := endpointLeaseApprovedAuthority()
	if p.Namespace != endpointlease.Namespace || p.UID == "" || reader == nil || validate == nil || approved == "" {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload endpointlease.Observation
	for i := range events {
		e := &events[i]
		if e.Trust != TrustTrusted || !e.TargetsPod || e.Type != endpointlease.RuleType ||
			e.Source != "redteam" || e.CreatorIdentity != endpointLeaseConsoleCreator || e.Name == "" || e.UID == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= endpointLeaseHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		candidate, err := endpointlease.ParseObservation(e.EndpointLeaseRaw)
		if err != nil || candidate.TargetPodUID != p.UID || candidate.ProxySourceSHA256 != approved ||
			candidate.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			e.CreatedAt.Sub(candidate.ObservedAt) > endpointLeaseHorizon ||
			e.CreatedAt.Add(e.Age).Sub(candidate.ObservedAt) >= endpointLeaseHorizon {
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
	live, err := validate(ctx, reader, payload.TargetPodUID, approved, image)
	if err != nil || live.ServiceUID != payload.ServiceUID || live.PolicyUID != payload.PolicyConfigMapUID ||
		live.SecretUID != payload.SecretUID || live.SeedSHA256 != payload.SeedSHA256 ||
		live.SourceSHA256 != payload.ProxySourceSHA256 || live.State.Revision != payload.PriorRevision {
		return
	}
	oldAllowed, retainedAllowed := false, false
	for _, id := range live.State.AllowedClientHMACs {
		oldAllowed = oldAllowed || id == payload.RevokedClientHMAC
		retainedAllowed = retainedAllowed || id == payload.RetainedClientHMAC
	}
	if !oldAllowed || !retainedAllowed {
		return
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: payload.PolicyName}, policy); err != nil ||
		string(policy.UID) != payload.PolicyUID || policy.Generation != payload.PolicyGeneration {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() {
		return
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, pod); err != nil ||
		string(pod.UID) != p.UID || !selector.Matches(labels.Set(pod.Labels)) {
		return
	}
	p.EndpointLeaseObservation = &model.EndpointLeaseObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		ScenarioID: payload.ScenarioID, EvidenceSource: payload.EvidenceSource,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		TargetPodUID: payload.TargetPodUID, ServiceUID: payload.ServiceUID,
		PolicyConfigMapUID: payload.PolicyConfigMapUID, ProxySourceSHA256: payload.ProxySourceSHA256,
		SecretUID: payload.SecretUID, SeedSHA256: payload.SeedSHA256, PriorRevision: payload.PriorRevision,
		RevokedClientHMAC: payload.RevokedClientHMAC, RetainedClientHMAC: payload.RetainedClientHMAC,
		AcceptedStatus: payload.AcceptedStatus, AcceptedResponseSHA256: payload.AcceptedResponseSHA256,
		RetainedBaselineStatus:         payload.RetainedBaselineStatus,
		RetainedBaselineResponseSHA256: payload.RetainedBaselineResponseSHA256,
		ObservedAt:                     payload.ObservedAt,
	}
}
