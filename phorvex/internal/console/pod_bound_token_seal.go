package console

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
)

// sealPodBoundTokenAudit runs once after the harness and coordinator terminate.
// The interval was already committed before cleanup. This method only selects
// those original bytes and stores the authenticated answer for later GETs.
func (rm *RunManager) sealPodBoundTokenAudit(id, out string) error {
	if rm.cfg.AuditSource == nil || rm.cfg.AuditSourceIdentity == "" {
		return errors.New("Pod-bound token authenticated audit source unavailable")
	}
	var start podBoundTokenAuditStart
	if _, err := readPodBoundJSON(out, "pod-bound-token-audit-start.json", &start); err != nil {
		return err
	}
	var committed podBoundTokenObservationCommitted
	commitRaw, err := readPodBoundJSON(out, podBoundObservationCommittedFile, &committed)
	if err != nil {
		return err
	}
	var observation podBoundTokenObservationEnd
	endRaw, err := readPodBoundJSON(out, podBoundObservationEndFile, &observation)
	if err != nil {
		return err
	}
	var request podBoundTokenRequest
	requestRaw, err := readPodBoundJSON(out, podBoundRequestFile, &request)
	if err != nil {
		return err
	}
	var barrier podBoundTokenBarrier
	barrierRaw, err := readPodBoundJSON(out, podBoundBarrierFile, &barrier)
	if err != nil {
		return err
	}
	var artifact podBoundTokenArtifact
	artifactRaw, err := readPodBoundJSON(out, podBoundArtifactFile, &artifact)
	if err != nil {
		return err
	}
	var terminal podBoundTokenTerminal
	if _, err := readPodBoundJSON(out, podBoundTerminalFile, &terminal); err != nil {
		return err
	}
	var eventCleanup podBoundTokenEventCleanup
	if _, err := readPodBoundJSON(out, podBoundEventCleanupFile, &eventCleanup); err != nil {
		return err
	}
	c := committed.Commitment
	if start.Schema != "pod-bound-token-audit-start-v1" || start.RunID != id ||
		start.Nonce != request.Nonce || start.SourceIdentity != rm.cfg.AuditSourceIdentity ||
		start.RequestSHA256 != podBoundHash(requestRaw) ||
		observation.Schema != "pod-bound-token-observation-end-v1" ||
		observation.RunID != id || observation.Nonce != request.Nonce ||
		observation.RequestSHA256 != start.RequestSHA256 ||
		observation.BarrierSHA256 != podBoundHash(barrierRaw) ||
		committed.Schema != "pod-bound-token-observation-committed-v1" ||
		committed.RunID != id || committed.Nonce != request.Nonce ||
		committed.RequestSHA256 != start.RequestSHA256 ||
		committed.BarrierSHA256 != observation.BarrierSHA256 ||
		committed.ObservationEndSHA256 != podBoundHash(endRaw) ||
		committed.SourceIdentity != start.SourceIdentity ||
		c.StartOffset != start.Offset || c.EndOffset <= c.StartOffset ||
		c.Segment.ID != start.Segment.ID ||
		c.Segment.Generation != start.Segment.Generation ||
		c.Segment.Anchor != start.Segment.Anchor ||
		barrier.DecisionRowSHA == "" || barrier.Event.UID == "" ||
		artifact.RequestSHA256 != start.RequestSHA256 ||
		artifact.BarrierSHA256 != observation.BarrierSHA256 ||
		artifact.ObservationEndedAt != observation.ObservationEndedAt ||
		terminal.ArtifactSHA256 != podBoundHash(artifactRaw) ||
		eventCleanup.EventUID != barrier.Event.UID ||
		eventCleanup.Status != "CONFIRMED_ABSENT" {
		return errors.New("Pod-bound token immutable audit commitment identities differ")
	}
	endTime, e1 := time.Parse(time.RFC3339Nano, observation.ObservationEndedAt)
	terminalTime, e2 := time.Parse(time.RFC3339Nano, terminal.FinishedAt)
	captureTime := time.Unix(0, c.CapturedAtUnixNano).UTC()
	if e1 != nil || e2 != nil || c.CapturedAtUnixNano <= 0 ||
		endTime.After(captureTime) || captureTime.After(terminalTime) {
		return errors.New("Pod-bound token audit commitment was not captured before cleanup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	exact, err := rm.cfg.AuditSource.SelectExact(ctx, audittransport.ExactWindowRequest{
		Segment: c.Segment, StartOffset: c.StartOffset, EndOffset: c.EndOffset,
		Namespace: request.Namespace, PodName: request.SourcePodName,
		PodUID: request.SourcePodUID, PolicyUID: request.PolicyUID, Commitment: &c})
	if err != nil {
		return fmt.Errorf("Pod-bound token committed audit window changed: %w", err)
	}
	found := false
	attributed := 0
	for _, row := range exact.Rows {
		decision, operation, err := podBoundTypedDecision(row.Raw, request, barrier.Event.UID)
		if err != nil && strings.Contains(err.Error(), "typed event attribution absent") {
			if podBoundCompetingUnattributedOperation(row.Raw) {
				return errors.New("Pod-bound token unattributed source operation confounds replay")
			}
			continue
		}
		if err != nil {
			return errors.New("Pod-bound token later exact target decision malformed")
		}
		attributed++
		if decision.SelectedAction != barrier.Decision.SelectedAction ||
			decision.DispatchOutcome != barrier.Decision.DispatchOutcome ||
			(decision.DispatchOutcome == "emitted" && decision.ID != barrier.Decision.ID) {
			return errors.New("Pod-bound token competing attributed decision in committed window")
		}
		rowAt, timeErr := podBoundDecisionRowTime(row.Raw)
		if timeErr != nil || rowAt.After(endTime) {
			return errors.New("Pod-bound token attributed decision escaped observation window")
		}
		if podBoundHash(row.Raw) != barrier.DecisionRowSHA {
			continue
		}
		if decision != barrier.Decision || operation != barrier.Operation {
			return errors.New("Pod-bound token retained decision projection differs")
		}
		if found {
			return errors.New("Pod-bound token duplicate selected decision row")
		}
		found = true
	}
	if !found || attributed == 0 {
		return errors.New("Pod-bound token selected decision omitted by committed window")
	}
	seal := podBoundTokenAuditSeal{Schema: "pod-bound-token-audit-seal-v1",
		RunID: id, Nonce: request.Nonce, SourceIdentity: committed.SourceIdentity,
		RequestSHA256: start.RequestSHA256, BarrierSHA256: observation.BarrierSHA256,
		ArtifactSHA256: terminal.ArtifactSHA256, ObservationCommitSHA256: podBoundHash(commitRaw),
		Exact: exact, SealedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	_, err = writePodBoundOwnedFile(out, podBoundSealFile, seal)
	return err
}
