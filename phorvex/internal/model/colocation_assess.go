package model

import (
	"sort"
	"strings"
	"time"
)

// FactColocation is M-34's untrusted colocation relation, distinct from the
// CoResidency scalar and the nodePlacement exposure clock. No numeric key is minted.
const FactColocation = "colocation"

// ColocationInput is the joined snapshot for observational fact recording only.
// The scorer never sees this inventory or the unresolved weight.
type ColocationInput struct {
	Target                       Pod
	TargetKnown                  bool
	Tenant, PolicyUID, PolicyKey string
	Peers                        []string
	Pods                         []Pod
	// Membership values are effective tenant keys until M-140. Multiple policy
	// matches remain ambiguous even if their tenant strings happen to coincide.
	Membership                                     map[string][]string
	NamespaceLabels                                map[string]map[string]string
	Events                                         map[string][]SecurityEventInfo
	PodsComplete, PoliciesComplete, EventsComplete bool
	UnresolvedEventTargets                         bool
	Now                                            time.Time
	CoverEnabled                                   bool
}

func AssessColocation(in ColocationInput) ColocationAssessment {
	out := ColocationAssessment{
		SchemaVersion: "phorvex.colocation.v1", Kind: "colocation-assessment",
		SnapshotTime: in.Now, Tenant: in.Tenant, PolicyUID: in.PolicyUID, PolicyKey: in.PolicyKey,
		IdentityBasis: "effective-tenant-until-M140", PeerPolicies: append([]string{}, in.Peers...),
		PodKey: in.Target.Namespace + "/" + in.Target.Name, PodUID: in.Target.UID, Node: in.Target.Node,
		Fact: FactColocation, State: "unknown", Reason: "target-placement-unavailable",
		ObservabilityBasis: "assumption", ThreatModel: "TM-1/TM-2/2026-09-06",
		PodInventoryComplete: in.PodsComplete, PolicyInventoryComplete: in.PoliciesComplete, EventInventoryComplete: in.EventsComplete,
		Neighbors: []ColocationNeighbor{}, Witnesses: []string{},
		Weight: UnresolvedColocationWeight{Status: "UNRESOLVED"}, ScoringReason: "weight-unresolved",
		CoverEnabled: in.CoverEnabled, CoverCondition: "unknown", CoverReason: "leader-shadow-binding-unavailable",
		Prerequisites:    []string{"T3-calibration-unresolved", "P-06-unverified", "P-03-unverified"},
		ExecutionOutcome: "not-admitted", EventAgeBinding: "eventHalfLife-unbound-to-current-linear-EventAgeHorizon",
	}
	sort.Strings(out.PeerPolicies)
	if !in.TargetKnown {
		return out
	}
	if in.Target.Node == "" {
		out.State = "absent"
		out.Reason = "target-unscheduled"
		return out
	}
	uncertain := !in.PodsComplete
	seen := map[string]bool{}
	for _, p := range in.Pods {
		key := p.Namespace + "/" + p.Name
		if key == out.PodKey || p.Node != in.Target.Node {
			continue
		}
		if seen[key] {
			uncertain = true
			continue
		}
		seen[key] = true
		n := classifyColocationNeighbor(in, p)
		out.Neighbors = append(out.Neighbors, n)
		if n.Class == "untrusted" {
			out.Witnesses = append(out.Witnesses, key)
		}
		if n.Class == "unknown" {
			uncertain = true
		}
	}
	sort.Slice(out.Neighbors, func(i, j int) bool { return out.Neighbors[i].PodKey < out.Neighbors[j].PodKey })
	sort.Strings(out.Witnesses)
	switch {
	case len(out.Witnesses) > 0:
		out.State = "present"
		out.Reason = "untrusted-coresident"
	case uncertain:
		out.Reason = "incomplete-placement-or-classification"
	default:
		out.State = "absent"
		out.Reason = "no-untrusted-coresident"
	}
	return out
}

func classifyColocationNeighbor(in ColocationInput, p Pod) ColocationNeighbor {
	key := p.Namespace + "/" + p.Name
	n := ColocationNeighbor{PodKey: key, PodUID: p.UID, Node: p.Node, Class: "unknown", Reason: "policy-membership-unavailable", OwnerKind: p.OwnerKind, Policies: append([]string{}, in.Membership[key]...), Events: []ColocationEvent{}}
	sort.Strings(n.Policies)
	ns, nsKnown := in.NamespaceLabels[p.Namespace]
	n.NamespaceTrustDeclaration = ns["phorvex.ai/trust-class"]
	// Without an authoritative age-rule binding a targeted trusted event cannot
	// certify active compromise OR its expiry. Preserve that uncertainty, rather
	// than silently substituting the linear horizon for the ruling's half-life.
	overrideUnknown := !in.EventsComplete || in.UnresolvedEventTargets
	for _, e := range in.Events[key] {
		if e.Trust != "trusted" || !e.TargetsPod {
			continue
		}
		overrideUnknown = true
		why := "age-rule-unbound"
		if e.TimestampMissing {
			why = "event-age-unavailable"
		}
		n.Events = append(n.Events, ColocationEvent{Name: e.Name, Source: e.Source, Target: key, AgeSeconds: e.Age.Seconds(), AgePresent: !e.TimestampMissing, Trust: e.Trust, Override: why})
	}
	sort.Slice(n.Events, func(i, j int) bool {
		a, b := n.Events[i], n.Events[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.AgeSeconds < b.AgeSeconds
	})
	baseClass, reason := "unknown", "policy-membership-unavailable"
	switch {
	case p.OwnerKind == "DaemonSet":
		baseClass, reason = "infrastructure", "daemonset-owner"
	case strings.HasPrefix(p.Namespace, "kube-"):
		baseClass, reason = "infrastructure", "kube-namespace"
	case nsKnown && n.NamespaceTrustDeclaration == "infrastructure":
		baseClass, reason = "infrastructure", "admin-namespace-declaration"
	case !nsKnown:
		reason = "namespace-declaration-unavailable"
	case !in.PoliciesComplete:
		reason = "policy-inventory-incomplete"
	case len(n.Policies) > 1:
		reason = "ambiguous-policy-membership"
	case len(n.Policies) == 0:
		baseClass, reason = "untrusted", "no-policy"
	default:
		owner := n.Policies[0]
		if owner == "" {
			break
		}
		baseClass, reason = "untrusted", "non-peer-policy"
		if owner == in.Tenant {
			baseClass, reason = "trusted", "own-tenant"
		}
		for _, peer := range in.Peers {
			if peer != "" && peer == owner {
				baseClass, reason = "trusted", "directional-peer"
			}
		}
	}
	if overrideUnknown && baseClass != "untrusted" {
		n.Reason = "compromise-override-unresolved"
		return n
	}
	n.Class, n.Reason = baseClass, reason
	return n
}

// WarmSwapObservation is a future verified logical-asset binding, not inferred
// from labels or a successful Delete call. The current runner supplies no binding.
type WarmSwapObservation struct {
	BindingKnown   bool
	Leader, Shadow Pod
	ShadowReady    bool
	// TriggerKnown distinguishes a verified event-free path from missing data.
	TriggerKnown, EventFree bool
	TriggerNode             string
}

// ColocationCoverCondition evaluates Q3's observed precondition only; even true
// does not authorize credit without the P-06 execution proof and T3/P-03 gates.
func ColocationCoverCondition(in ColocationInput, b WarmSwapObservation) (string, string) {
	if !b.BindingKnown || b.Leader.Node == "" || b.Shadow.Node == "" || b.Leader.UID == "" || b.Shadow.UID == "" {
		return "unknown", "leader-shadow-binding-unavailable"
	}
	if !b.ShadowReady {
		return "false", "shadow-not-ready"
	}
	if b.Leader.Node == b.Shadow.Node {
		return "false", "same-node"
	}
	if !b.TriggerKnown || (!b.EventFree && b.TriggerNode == "") {
		return "unknown", "trigger-location-unavailable"
	}
	if !b.EventFree && b.Shadow.Node == b.TriggerNode {
		return "false", "trigger-node"
	}
	uncertain := !in.PodsComplete
	shadowSeen := false
	for _, p := range in.Pods {
		if p.Node != b.Shadow.Node {
			continue
		}
		if p.UID == b.Shadow.UID {
			shadowSeen = true
		}
		n := classifyColocationNeighbor(in, p) // includes the shadow itself
		if n.Class == "untrusted" {
			return "false", "untrusted-destination"
		}
		if n.Class == "unknown" {
			uncertain = true
		}
	}
	if uncertain || !shadowSeen {
		return "unknown", "incomplete-destination-observations"
	}
	return "true", "observed-safe-destination"
}
