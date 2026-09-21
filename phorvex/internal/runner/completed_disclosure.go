package runner

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/model"
)

const defaultLossHistoryReadTimeout = 100 * time.Millisecond

func (m *Manager) lossHistoryReader() client.Reader {
	if m.LossHistoryReader != nil {
		return m.LossHistoryReader
	}
	return m.BoundaryReader
}

func (m *Manager) admitCompletedDisclosures(ctx context.Context, events []model.SecurityEventInfo, p model.Policy, now time.Time) []string {
	return m.admitCompletedDisclosuresWithReader(ctx, m.lossHistoryReader(), events, p, now)
}

func (m *Manager) admitCompletedDisclosuresWithReader(ctx context.Context, reader client.Reader, events []model.SecurityEventInfo, p model.Policy, now time.Time) []string {
	return ingest.AdmitCompletedDisclosures(ctx, reader, m.LossHistory, events, p, now, m.Log)
}

type representationHistoryInput struct {
	owner  model.ObjectIdentity
	result losshistory.Result
	gaps   []string
}

func (m *Manager) representationHistoryInputs(ctx context.Context, decisions []model.Decision, versions map[string]string, p model.Policy, ingestGaps []string) map[string]representationHistoryInput {
	return m.representationHistoryInputsWithReader(ctx, m.lossHistoryReader(), decisions, versions, p, ingestGaps)
}

func (m *Manager) representationHistoryInputsWithReader(ctx context.Context, reader client.Reader, decisions []model.Decision, versions map[string]string, p model.Policy, ingestGaps []string) map[string]representationHistoryInput {
	out := make(map[string]representationHistoryInput, len(decisions))
	for _, d := range decisions {
		key := d.Namespace + "/" + d.Pod
		entry := representationHistoryInput{gaps: append([]string(nil), ingestGaps...)}
		_, stable, err := ingest.ResolveStableWorkloadOwner(ctx, reader, d.Namespace, d.Pod, versions[key])
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

func unavailableHistoryInputs(decisions []model.Decision, gap string) map[string]representationHistoryInput {
	out := make(map[string]representationHistoryInput, len(decisions))
	for _, d := range decisions {
		key := d.Namespace + "/" + d.Pod
		out[key] = representationHistoryInput{
			result: losshistory.Result{Status: "unavailable", Gaps: []string{gap}},
			gaps:   []string{gap + ":" + key},
		}
	}
	return out
}

// prepareRepresentationSnapshots gives optional loss-history API work one
// bounded context separate from the tick. Timeout degrades the retained-history
// assessment explicitly while leaving the original context and actuation path
// available.
func (m *Manager) prepareRepresentationSnapshots(
	ctx context.Context,
	decisions []model.Decision,
	p model.Policy,
	versions map[string]string,
	claim model.ClaimScope,
	inventory *model.ExistentialInventory,
	events []model.SecurityEventInfo,
	now time.Time,
) ([]model.RepresentationSnapshot, map[string]representationHistoryInput, bool) {
	if m.LossHistory == nil {
		snapshots, complete := representationSnapshotsBeforeEffect(ctx, decisions, p, versions, claim, inventory)
		return snapshots, nil, complete
	}
	timeout := m.LossHistoryReadTimeout
	if timeout <= 0 {
		timeout = defaultLossHistoryReadTimeout
	}
	if ctx.Err() != nil {
		return nil, nil, false
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 2*timeout {
		histories := unavailableHistoryInputs(decisions, "retained-loss-history-budget-unavailable")
		snapshots, complete := representationSnapshotsBeforeEffect(ctx, decisions, p, versions, claim, inventory, histories)
		return snapshots, histories, complete
	}
	historyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	reader := m.lossHistoryReader()
	ingestGaps := m.admitCompletedDisclosuresWithReader(historyCtx, reader, events, p, now)
	histories := m.representationHistoryInputsWithReader(historyCtx, reader, decisions, versions, p, ingestGaps)
	if historyCtx.Err() != nil {
		histories = unavailableHistoryInputs(decisions, "retained-loss-history-read-timeout")
	}
	snapshots, complete := representationSnapshotsBeforeEffect(ctx, decisions, p, versions, claim, inventory, histories)
	return snapshots, histories, complete
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
