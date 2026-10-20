package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

const crmRefundHorizon = 60 * time.Second
const crmConsoleCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"

// bindCRMRefundObservation grants the crm-refund-revoke candidate fact only for one fresh
// trusted cross-record-refund-abuse event whose typed identities match the live deny-guard,
// Service, selecting policy and the target Pod. Any competing assertion suppresses the fact.
// The authoritative re-check still happens at enact time in crmRefundAuthority.
func bindCRMRefundObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.CRMRefundObservation = nil
	if p.Namespace != crmrefund.Namespace || p.UID == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload crmrefund.Observation
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorCRMRefundAbuse ||
			e.CreatorIdentity != crmConsoleCreator || e.Name == "" || e.UID == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= crmRefundHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		candidate, parseErr := crmrefund.ParseObservation(e.CRMRefundRaw)
		if parseErr != nil || candidate.TargetPodUID != p.UID || candidate.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			e.CreatedAt.Sub(candidate.ObservedAt) > crmRefundHorizon ||
			e.CreatedAt.Add(e.Age).Sub(candidate.ObservedAt) >= crmRefundHorizon {
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
	live, e := crmrefund.ValidateLive(ctx, reader, payload.TargetPodUID, payload.PeerPodUID)
	_, alreadyDenied := live.State.Entry(payload.OrderID)
	if e != nil || alreadyDenied || len(live.State.Entries) >= 256 ||
		live.GuardUID != payload.GuardConfigMapUID || live.ServiceUID != payload.ServiceUID {
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
	p.CRMRefundObservation = &model.CRMRefundObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		OrderID: payload.OrderID, OrderAccountID: payload.OrderAccountID, CallerAccountID: payload.CallerAccountID,
		GuardConfigMapUID: payload.GuardConfigMapUID, ServiceUID: payload.ServiceUID,
		TargetPodUID: payload.TargetPodUID, PeerPodUID: payload.PeerPodUID,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		ObservedAt: payload.ObservedAt,
	}
}
