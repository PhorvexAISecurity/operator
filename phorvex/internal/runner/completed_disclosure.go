package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/model"
)

func (m *Manager) admitCompletedDisclosures(ctx context.Context, events []model.SecurityEventInfo, p model.Policy, now time.Time) []string {
	return ingest.AdmitCompletedDisclosures(ctx, m.BoundaryReader, m.LossHistory, events, p, now, m.Log)
}

type representationHistoryInput struct {
	owner  model.ObjectIdentity
	result losshistory.Result
	gaps   []string
}

func (m *Manager) representationHistoryInputs(ctx context.Context, decisions []model.Decision, versions map[string]string, p model.Policy, ingestGaps []string) map[string]representationHistoryInput {
	out := make(map[string]representationHistoryInput, len(decisions))
	for _, d := range decisions {
		key := d.Namespace + "/" + d.Pod
		entry := representationHistoryInput{gaps: append([]string(nil), ingestGaps...)}
		_, stable, err := ingest.ResolveStableWorkloadOwner(ctx, m.BoundaryReader, d.Namespace, d.Pod, versions[key])
		if err != nil {
			entry.result = losshistory.Result{Status: "unavailable", Gaps: []string{"stable-workload-owner-unavailable"}}
			entry.gaps = append(entry.gaps, fmt.Sprintf("stable-workload-owner-unavailable:%s", key))
			out[key] = entry
			continue
		}
		entry.owner = stable
		entry.result = m.LossHistory.Query(p.PolicyUID, stable.UID)
		out[key] = entry
	}
	return out
}

func admittedWitness(r model.AdmittedLossV1) model.LossWitness {
	p := r.Disclosure
	policyEpoch, decisionAsset := p.PolicyEpoch, p.DecisionAsset
	immediate, stable, classification, observation := p.ImmediateController, p.StableWorkloadOwner, p.Classification, p.Observation
	return model.LossWitness{
		SchemaVersion: model.AdmittedLossSchemaV1, EvidenceID: p.EvidenceID,
		PolicyEpoch: &policyEpoch, DecisionAsset: &decisionAsset,
		ImmediateController: &immediate, StableWorkloadOwner: &stable,
		Classification: &classification, Observation: &observation, CanonicalPayloadSHA256: r.CanonicalPayloadSHA256,
		SecurityEventUID: r.SecurityEvent.UID, Scope: p.ProtectedScope,
		EventRef: r.SecurityEvent.Name, EventTime: r.SecurityEvent.CreationTimestamp.Format(time.RFC3339Nano),
		IngestionTime: r.IngestedAt.Format(time.RFC3339Nano), AuthenticatedIdentity: r.AuthenticatedCreator,
		TrustAtIngestionRef: r.TrustBoundary.ConfigurationUID + "/" + r.TrustBoundary.ConfigurationResourceVersion,
		RuleVersion:         p.Classification.RuleVersion, PayloadPredicateRef: r.CanonicalPayloadSHA256,
		CompletedUnauthorizedOutcomeRef: p.Observation.ObservedSHA256,
		IrreversibilitySemantics:        "completed-external-copy-cannot-be-revoked-by-source-rotation",
		ClassificationRef:               p.Classification.RuleDigest,
	}
}
