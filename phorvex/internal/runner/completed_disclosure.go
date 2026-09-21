package runner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
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

type lossHistoryJob struct {
	reader    client.Reader
	store     losshistory.Ledger
	decisions []model.Decision
	versions  map[string]string
	policy    model.Policy
	events    []model.SecurityEventInfo
	now       time.Time
	timeout   time.Duration
	log       logr.Logger
	response  chan map[string]representationHistoryInput
}

type lossHistoryCoordinator struct {
	mu   sync.Mutex
	busy bool
}

func newLossHistoryCoordinator() *lossHistoryCoordinator {
	return &lossHistoryCoordinator{}
}

func (c *lossHistoryCoordinator) submit(job lossHistoryJob) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy {
		return false
	}
	c.busy = true
	// At most one worker exists. If a PVC call ignores cancellation and stalls,
	// every later tick reports worker-busy instead of accumulating timeout
	// goroutines or blocking defensive dispatch behind the same filesystem lock.
	go func() {
		workCtx, cancel := context.WithTimeout(context.Background(), job.timeout)
		gaps := ingest.AdmitCompletedDisclosures(workCtx, job.reader, job.store, job.events, job.policy, job.now, job.log)
		histories := representationHistoryInputsWithStore(workCtx, job.reader, job.store, job.decisions, job.versions, job.policy, gaps)
		timedOut := workCtx.Err() != nil
		cancel()
		if timedOut {
			histories = unavailableHistoryInputs(job.decisions, "retained-loss-history-read-timeout")
		}
		c.mu.Lock()
		c.busy = false
		c.mu.Unlock()
		job.response <- histories
	}()
	return true
}

func (m *Manager) getLossHistoryCoordinator() *lossHistoryCoordinator {
	m.lossHistoryWorkerMu.Lock()
	defer m.lossHistoryWorkerMu.Unlock()
	if m.lossHistoryWorker == nil {
		m.lossHistoryWorker = newLossHistoryCoordinator()
	}
	return m.lossHistoryWorker
}

func (m *Manager) representationHistoryInputs(ctx context.Context, decisions []model.Decision, versions map[string]string, p model.Policy, ingestGaps []string) map[string]representationHistoryInput {
	return representationHistoryInputsWithStore(ctx, m.lossHistoryReader(), m.LossHistory, decisions, versions, p, ingestGaps)
}

func representationHistoryInputsWithStore(ctx context.Context, reader client.Reader, store losshistory.Ledger, decisions []model.Decision, versions map[string]string, p model.Policy, ingestGaps []string) map[string]representationHistoryInput {
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
		entry.result = store.Query(p.PolicyUID, stable.UID)
		filtered := entry.result.Records[:0]
		for _, record := range entry.result.Records {
			if record.Disclosure.ProtectedScope.Tenant != p.Tenant {
				entry.gaps = append(entry.gaps, "retained-loss-history-current-tenant-mismatch:"+record.Disclosure.EvidenceID)
				continue
			}
			filtered = append(filtered, record)
		}
		entry.result.Records = filtered
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

// prepareRepresentationSnapshots gives all optional loss-history API and
// durable-store work one singleflight worker separate from the tick. Timeout
// degrades the retained-history assessment explicitly while leaving the
// original context and actuation path available.
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
	deadlineLow := false
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 2*timeout {
		deadlineLow = true
	}
	decisionCopy := make([]model.Decision, len(decisions))
	for i := range decisions {
		decisionCopy[i].Namespace, decisionCopy[i].Pod = decisions[i].Namespace, decisions[i].Pod
	}
	versionCopy := make(map[string]string, len(versions))
	for key, version := range versions {
		versionCopy[key] = version
	}
	eventCopy := append([]model.SecurityEventInfo(nil), events...)
	for i := range eventCopy {
		eventCopy[i].ResolvedTargets = append([]string(nil), eventCopy[i].ResolvedTargets...)
		eventCopy[i].UnresolvedTargets = append([]string(nil), eventCopy[i].UnresolvedTargets...)
	}
	response := make(chan map[string]representationHistoryInput, 1)
	job := lossHistoryJob{reader: m.lossHistoryReader(), store: m.LossHistory, decisions: decisionCopy, versions: versionCopy,
		policy: p, events: eventCopy, now: now, timeout: timeout, log: m.Log, response: response}
	if !m.getLossHistoryCoordinator().submit(job) {
		histories := unavailableHistoryInputs(decisions, "retained-loss-history-worker-busy")
		snapshots, complete := representationSnapshotsBeforeEffect(ctx, decisions, p, versions, claim, inventory, histories)
		return snapshots, histories, complete
	}
	if deadlineLow {
		histories := unavailableHistoryInputs(decisions, "retained-loss-history-budget-unavailable")
		snapshots, complete := representationSnapshotsBeforeEffect(ctx, decisions, p, versions, claim, inventory, histories)
		return snapshots, histories, complete
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var histories map[string]representationHistoryInput
	select {
	case histories = <-response:
	case <-timer.C:
		histories = unavailableHistoryInputs(decisions, "retained-loss-history-work-timeout")
	case <-ctx.Done():
		return nil, nil, false
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
		AdmissionTime: r.AdmissionTime.Format(time.RFC3339Nano),
		IngestionTime: r.IngestedAt.Format(time.RFC3339Nano), AuthenticatedIdentity: r.AuthenticatedCreator,
		TrustAtIngestionRef: r.TrustBoundary.ConfigurationUID + "/" + r.TrustBoundary.ConfigurationResourceVersion,
		RuleVersion:         p.Classification.RuleVersion, PayloadPredicateRef: r.CanonicalPayloadSHA256,
		CompletedUnauthorizedOutcomeRef: p.Observation.ObservedSHA256,
		IrreversibilitySemantics:        "completed-external-copy-cannot-be-revoked-by-source-rotation",
		ClassificationRef:               p.Classification.RuleDigest,
	}
}
