package runner

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func replayWorkloadUID(view *model.WorkloadView) string {
	if view != nil && view.Pod.WorkloadSpec.Known {
		return view.Pod.WorkloadSpec.Workload.UID
	}
	return ""
}

// replayCostEvidence is optional observability only. Point EndpointSlice
// membership and Pod.ReadyAt are insufficient to manufacture move-attributed
// endpoint-loss intervals, so this producer deliberately keeps that status
// unavailable. Nothing in selection or admission reads this envelope.
func (m *Manager) replayCostEvidence(views []*model.WorkloadView, pol model.Policy, spec v1alpha1.PhorvexPolicySpec, at time.Time) *model.ReplayCostEvidence {
	if !m.CaptureCostEvidence {
		return nil
	}
	out := &model.ReplayCostEvidence{
		Schema: model.ReplayCostEvidenceSchema, CapturedAt: at, PolicyOwner: pol.Owner(), PolicyUID: pol.PolicyUID,
		EndpointLossStatus: "unavailable", AdmissionLedgerStatus: "not-authoritative",
		Missing: []string{"endpoint-loss-intervals:not-recorded", "authoritative-endpoint-budget-ledger:not-recorded",
			"accepted-endpoint-availability-target:not-recorded", "replica-history:in-memory-and-incomplete"},
	}
	if spec.SLO.Window.Duration <= 0 {
		out.Missing = append(out.Missing, "accepted-slo-window:unavailable")
	}
	if pol.PolicyUID == "" {
		out.Missing = append(out.Missing, "policy-uid:unavailable")
	}
	for i, view := range views {
		if i == 256 {
			out.WorkloadsTruncated = true
			out.Missing = append(out.Missing, "workload-specs:capture-count-limit")
			break
		}
		if view == nil {
			out.Missing = append(out.Missing, "workload-view:unavailable")
			continue
		}
		out.Workloads = append(out.Workloads, model.ReplayWorkloadSpec{PodUID: view.Pod.UID, Observation: view.Pod.WorkloadSpec})
		if !view.Pod.WorkloadSpec.Known {
			reason := view.Pod.WorkloadSpec.Reason
			if reason == "" {
				reason = "not-recorded"
			}
			out.Missing = append(out.Missing, fmt.Sprintf("workload-spec[%s]:%s", view.Pod.UID, reason))
		}
	}
	out.ReplicaHistory = m.Disruption.SnapshotForReplay(pol.Tenant, pol.Namespace, pol.Owner(), at, model.MaxReplayHistoryEntries)
	if !out.ReplicaHistory.Available {
		out.Missing = append(out.Missing, "replica-history:unavailable")
	}
	if out.ReplicaHistory.Truncated {
		out.Missing = append(out.Missing, "replica-history:truncated")
	}
	if out.ReplicaHistory.UnattributedEntries > 0 {
		out.Missing = append(out.Missing, "replica-history:policy-attribution-unavailable")
	}
	if out.ReplicaHistory.FutureEntries > 0 {
		out.Missing = append(out.Missing, "replica-history:observations-after-snapshot-excluded")
	}
	if out.ReplicaHistory.ProcessObservedSince.IsZero() {
		out.Missing = append(out.Missing, "replica-history:process-start-unavailable")
	}
	if out.ReplicaHistory.ProcessObservedSince.After(at) {
		out.Missing = append(out.Missing, "replica-history:process-start-after-snapshot")
	}
	for _, row := range out.ReplicaHistory.Entries {
		if row.WorkloadUID == "" {
			out.Missing = append(out.Missing, "replica-history:workload-attribution-unavailable")
			break
		}
	}
	if raw, err := json.Marshal(out); err != nil || len(raw) > model.MaxReplayEvidenceBytes {
		out.Workloads, out.ReplicaHistory.Entries = nil, nil
		out.WorkloadsTruncated, out.ReplicaHistory.Truncated, out.CaptureByteLimit = true, true, true
		out.Missing = []string{"endpoint-cost-evidence:capture-byte-limit", "endpoint-loss-intervals:not-recorded", "authoritative-endpoint-budget-ledger:not-recorded"}
	}
	return out
}
