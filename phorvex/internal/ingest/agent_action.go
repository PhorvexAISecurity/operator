package ingest

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/agentdeny"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

const agentActionHorizon = 5 * time.Minute

// bindAgentActionDenyObservation grants the agent-action-deny candidate fact only for one
// fresh TRUSTED agent-action-abuse event whose typed identities match the live deny-guard,
// Service, selecting policy and the target Pod — in the Pod's OWN namespace (parametric: no
// hard-coded app namespace). Unlike crm-refund-revoke it does not pin a specific injector
// identity; any allowlisted trusted detector (e.g. an isolated lane's) is honored, with the
// console-target-pod-UID binding still required and the authoritative re-check still done at
// enact time in agentActionAuthority. Any competing assertion suppresses the fact.
func bindAgentActionDenyObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.AgentActionDenyObservation = nil
	if p.Namespace == "" || p.UID == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload agentdeny.Observation
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorAgentActionAbuse ||
			e.CreatorIdentity == "" || e.Name == "" || e.UID == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= agentActionHorizon || e.ConsoleTargetPodUID != p.UID {
			continue
		}
		candidate, parseErr := agentdeny.ParseObservation(e.AgentActionRaw)
		if parseErr != nil || candidate.Namespace != p.Namespace || candidate.TargetPodUID != p.UID ||
			candidate.ObservedAt.After(e.CreatedAt.Add(time.Second)) ||
			e.CreatedAt.Sub(candidate.ObservedAt) > agentActionHorizon ||
			e.CreatedAt.Add(e.Age).Sub(candidate.ObservedAt) >= agentActionHorizon {
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
	live, e := agentdeny.ValidateLive(ctx, reader, payload.Namespace, payload.TargetPodUID)
	_, alreadyDenied := live.State.Entry(agentdeny.ActionKey(payload.CallerID, payload.ActionID))
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
	p.AgentActionDenyObservation = &model.AgentActionDenyObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		Namespace: payload.Namespace, AgentName: payload.AgentName,
		CallerID: payload.CallerID, ActionID: payload.ActionID,
		GuardConfigMapUID: payload.GuardConfigMapUID, ServiceUID: payload.ServiceUID,
		TargetPodUID: payload.TargetPodUID,
		PolicyName: payload.PolicyName, PolicyUID: payload.PolicyUID, PolicyGeneration: payload.PolicyGeneration,
		ObservedAt: payload.ObservedAt,
	}
}
