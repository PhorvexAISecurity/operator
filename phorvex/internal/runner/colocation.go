package runner

import (
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// colocationInput joins actual policy selectors, namespace declarations and the
// authenticated M-94 event projection. It does not use the namespace-count scalar.
func colocationInput(obs *sensorapi.Observation, e *policyEntry) recon.ColocationInput {
	in := recon.ColocationInput{Tenant: e.tenant, PolicyUID: e.uid, PolicyKey: e.key.String(), Peers: e.spec.Trust.PeerPolicies,
		Now: obs.Now, Pods: obs.Pods, NamespaceLabels: obs.NamespaceLabels, Events: obs.EventByPod,
		PodsComplete: obs.PodInventoryComplete, PoliciesComplete: obs.PolicyInventoryComplete && obs.PolicySelectorsValid,
		EventsComplete: obs.EventInventoryComplete, CoverEnabled: e.spec.Cover.WarmSwap.Enabled,
		Membership: make(map[string][]string, len(obs.PolicyMembership)),
	}
	for _, ev := range obs.EvidenceEvents {
		if ev.Trust == ingest.TrustTrusted && len(ev.UnresolvedTargets) > 0 {
			in.UnresolvedEventTargets = true
		}
	}
	for key, tenants := range obs.PolicyMembership {
		in.Membership[key] = append([]string(nil), tenants...)
	}
	return in
}

func (m *Manager) recordColocation(in recon.ColocationInput, d model.Decision, pol model.Policy) {
	if m.Audit == nil {
		return
	}
	for _, p := range in.Pods {
		if p.Namespace == d.Namespace && p.Name == d.Pod {
			in.Target = p
			in.TargetKnown = true
			break
		}
	}
	a := recon.AssessColocation(in)
	a.GitSHA = pol.GitSHA
	a.BrainImage = pol.BrainImage
	a.TickID = pol.TickID
	if d.Trace != nil {
		a.DecisionID = d.Trace.DecisionID
	}
	if a.DecisionID == "" {
		a.DecisionID = deterministicTraceID("colocation", pol.TickID, d.Namespace, d.Pod)
	}
	m.Audit.Colocation(a)
}
