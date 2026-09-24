package model

import (
	"strings"
	"time"
)

// PodBoundAPIAuthEventEligible is the common admission boundary for the narrow
// credential vector. In production Trust is derived from the API-admission
// creator stamp, not the event's self-declared rule.source. The event can steer
// only an independently observed, current projected-token capability; it is
// still a detector observation, not proof of bearer theft or revocation.
func PodBoundAPIAuthEventEligible(e SecurityEventInfo, pod Pod, horizon time.Duration) bool {
	if !pod.HasPodBoundKubeAPIAuth() || e.Type != AttackVectorPodBoundAPIAuth ||
		e.Trust != "trusted" || strings.TrimSpace(e.CreatorIdentity) == "" ||
		e.Name == "" || e.UID == "" || !e.TargetsPod ||
		e.ConsoleTargetPodUID != pod.UID || e.TargetBindingReason != "" ||
		len(e.ResolvedTargets) != 1 || e.ResolvedTargets[0] != pod.Namespace+"/"+pod.Name ||
		len(e.UnresolvedTargets) != 0 ||
		e.TimestampMissing || e.CreatedAt.IsZero() || e.Age < 0 {
		return false
	}
	if horizon <= 0 {
		horizon = DefaultEventAgeHorizon
	}
	return EventAgeWeight(e.Age, horizon) > 0
}
