package runner

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// colocationInput joins actual policy selectors, namespace declarations and the
// authenticated M-94 event projection. It does not use the namespace-count scalar.
func colocationInput(snap *ingest.Snapshot, e *policyEntry) recon.ColocationInput {
	in := recon.ColocationInput{Tenant: e.tenant, PolicyUID: e.uid, PolicyKey: e.key.String(), Peers: e.spec.Trust.PeerPolicies,
		Now: snap.Now, Pods: snap.Pods, NamespaceLabels: snap.NamespaceLabels, Events: snap.EventByPod,
		PodsComplete: snap.PodInventoryComplete, PoliciesComplete: snap.PolicyInventoryComplete, EventsComplete: snap.EventInventoryComplete,
		CoverEnabled: e.spec.Cover.WarmSwap.Enabled, Membership: map[string][]string{},
	}
	for _, ev := range ingest.EvidenceEvents(snap.Events) {
		if ev.Trust == ingest.TrustTrusted && len(ev.UnresolvedTargets) > 0 {
			in.UnresolvedEventTargets = true
		}
	}
	for _, p := range snap.Policies {
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.Selector)
		if err != nil {
			in.PoliciesComplete = false
			continue
		}
		for _, pod := range snap.Pods {
			if pod.Namespace == p.Namespace && sel.Matches(labels.Set(pod.Labels)) {
				key := pod.Namespace + "/" + pod.Name
				in.Membership[key] = append(in.Membership[key], p.EffectiveTenant())
			}
		}
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
